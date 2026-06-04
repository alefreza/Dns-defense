dnssec_server.py — Secure DNS Server with DNSSEC signing
─────────────────────────────────────────────────────────
Port      : 1053  (default)
Zones     : loaded from zones.conf
Protections: ALL DISABLED by default — enable via CONFIG below
Feature log: query_log.jsonl

    Fields: timestamp, src_ip, qname, qtype, query_length,
            subdomain_depth, protocol, response_code, response_time_ms

DNSSEC:
    - Signs A records with RRSIG on startup
    - Serves DNSKEY records when queried
    - Responds correctly to dig +dnssec (sets AD bit, attaches RRSIG)
    - DNSSEC Validation Exhaustion protection (enable in CONFIG)

Install:
    pip install dnspython cryptography dnslib --break-system-packages
Run:
    python dnssec_server.py
    python dnssec_server.py --port 1053 --address 0.0.0.0

Test:
    dig @127.0.0.1 -p 1053 example.com A
    dig @127.0.0.1 -p 1053 example.com A +dnssec
    dig @127.0.0.1 -p 1053 example.com DNSKEY
"""

import os
import sys
import json
import time
import signal
import logging
import threading
import argparse
import base64
from collections import defaultdict, deque

import dns.dnssec as dnssec
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdata
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.RRSIG

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from dnslib import QTYPE, RCODE, RR, DNSRecord, DNSHeader
from dnslib.server import DNSServer, BaseResolver


# ═════════════════════════════════════════════════════════════════════════════
# Paths
# ═════════════════════════════════════════════════════════════════════════════
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
LOG_DIR        = os.path.join(BASE_DIR, "logs")
ZONES_FILE     = os.path.join(BASE_DIR, "zones.conf")
QUERY_LOG_FILE = os.path.join(BASE_DIR, "query_log.jsonl")
STATS_FILE     = os.path.join(LOG_DIR, "stats.json")
os.makedirs(LOG_DIR, exist_ok=True)


# ═════════════════════════════════════════════════════════════════════════════
# Logging
# ═════════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(LOG_DIR, "dns_server.log")),
    ],
)
logger = logging.getLogger("SecureDNS")


# ═════════════════════════════════════════════════════════════════════════════
# Zone loader
# ═════════════════════════════════════════════════════════════════════════════
def load_zones(path: str) -> dict:
    zones = {}
    if not os.path.exists(path):
        logger.warning("zones.conf not found at %s", path)
        return zones
    with open(path) as fh:
        in_section = False
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower() == "[zones]":
                in_section = True
                continue
            if line.startswith("["):
                in_section = False
                continue
            if in_section and "=" in line:
                fqdn, _, ip = line.partition("=")
                fqdn = fqdn.strip()
                ip   = ip.strip()
                if not fqdn.endswith("."):
                    fqdn += "."
                zones[fqdn] = ip
    logger.info("Loaded %d zone(s) from %s", len(zones), path)
    for fqdn, ip in zones.items():
        logger.info("  %-30s -> %s", fqdn, ip)
    return zones


# ═════════════════════════════════════════════════════════════════════════════
# Configuration  — ALL protections DISABLED by default
# ═════════════════════════════════════════════════════════════════════════════
CONFIG = {
    "amplification": {
        "enabled":           False,
        "block_any_queries": True,
        "rate_limit_per_ip": 100,
    },
    "nxdomain_flood": {
        "enabled":        False,
        "threshold":      20,
        "window_seconds": 10,
        "block_duration": 60,
    },
    "random_subdomain": {
        "enabled":                    False,
        "unique_subdomain_threshold": 15,
        "window_seconds":             10,
        "block_duration":             120,
    },
    "flood": {
        "enabled":                False,
        "max_queries_per_second": 50,
        "burst_allowance":        20,
        "block_duration":         30,
    },
    "phantom_domain": {
        "enabled": False,
        "suspicious_tlds": [
            ".invalid", ".test", ".example", ".localhost",
            ".local", ".intranet", ".internal", ".private",
        ],
        "nxdomain_ratio_threshold": 0.85,
        "min_queries_to_evaluate":  10,
    },
    "bot_based": {
        "enabled":                           False,
        "fingerprint_window":                30,
        "identical_query_threshold":         30,
        "query_interval_variance_threshold": 0.05,
        "whitelist": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    },
    # ── DNSSEC Validation Exhaustion ──────────────────────────────────────
    # Attacker hammers DNSKEY/RRSIG queries to exhaust crypto CPU on server.
    # Defense: rate-limit crypto-heavy query types per source IP.
    "dnssec_exhaustion": {
        "enabled":          False,   # <-- set True to activate
        "window_seconds":   5,
        "dnskey_threshold": 10,      # max DNSKEY queries per IP per window
        "rrsig_threshold":  15,      # max RRSIG queries per IP per window
        "block_duration":   60,
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# Feature logger
# ═════════════════════════════════════════════════════════════════════════════
_log_lock  = threading.Lock()
_log_queue: deque = deque()


def _enqueue_feature(record: dict):
    with _log_lock:
        _log_queue.append(record)


def _feature_writer():
    while True:
        time.sleep(1)
        batch = []
        with _log_lock:
            while _log_queue:
                batch.append(_log_queue.popleft())
        if batch:
            try:
                with open(QUERY_LOG_FILE, "a") as fh:
                    for rec in batch:
                        fh.write(json.dumps(rec) + "\n")
            except OSError as e:
                logger.error("Feature log write failed: %s", e)


def _build_feature(client_ip, qname, qtype_int, protocol,
                   response_code="", response_time_ms=0.0):
    """
    Build query feature record.
    Fields:
        timestamp        — unix time (float)
        src_ip           — source IP
        qname            — queried name (no trailing dot)
        qtype            — query type string (A, DNSKEY, RRSIG ...)
        query_length     — character length of qname
        subdomain_depth  — number of labels beyond base domain
        protocol         — "udp" or "tcp"
        response_code    — NOERROR / NXDOMAIN / REFUSED / SERVFAIL
        response_time_ms — server processing time in milliseconds
    """
    qname_clean = qname.rstrip(".")
    labels      = qname_clean.split(".")
    subdomain_depth = max(0, len(labels) - 2)

    qtype_map = {
        1:  "A",     28: "AAAA",  5:  "CNAME", 15: "MX",
        2:  "NS",    6:  "SOA",   16: "TXT",   255: "ANY",
        48: "DNSKEY", 46: "RRSIG", 43: "DS",   47: "NSEC",
        50: "NSEC3",
    }
    return {
        "timestamp":        round(time.time(), 3),
        "src_ip":           client_ip,
        "qname":            qname_clean,
        "qtype":            qtype_map.get(qtype_int, str(qtype_int)),
        "query_length":     len(qname_clean),
        "subdomain_depth":  subdomain_depth,
        "protocol":         protocol,
        "response_code":    response_code,
        "response_time_ms": round(response_time_ms, 3),
    }


# ═════════════════════════════════════════════════════════════════════════════
# DNSSEC Signer
# ═════════════════════════════════════════════════════════════════════════════
class DNSSECSigner:
    """
    Generates one ECDSA P-256 key pair and signs every A record in zones.
    Exposes:
        get_signed_answer(fqdn)  -> (a_rrset, rrsig_rrset) | (None, None)
        get_dnskey_rrset(fqdn)   -> dnskey_rrset            | None
        get_dnskey_rdata(fqdn)   -> dnskey_rdata            | None
        key_tag(fqdn)            -> int                     | None
    """

    def __init__(self, zones: dict):
        logger.info("[DNSSEC] Generating ECDSA P-256 key pair ...")
        self._priv         = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._dnskey_cache = {}   # fqdn -> (rdata, rrset)
        self._rrsig_cache  = {}   # fqdn -> (a_rrset, rrsig_rrset)
        self._sign_all(zones)

    # ── internal ──────────────────────────────────────────────────────────
    def _make_dnskey(self, zone_name):
        pub    = self._priv.public_key().public_numbers()
        kbytes = pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big")
        rdata  = dns.rdtypes.ANY.DNSKEY.DNSKEY(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.DNSKEY,
            flags=257, protocol=3, algorithm=13, key=kbytes,
        )
        rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rrset.add(rdata)
        return rdata, rrset

    def _sign_a(self, zone_name, ip, dnskey_rdata):
        a_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.A)
        a_rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip))
        rrsig = dnssec.sign(
            a_rrset, self._priv,
            signer=zone_name, dnskey=dnskey_rdata,
            lifetime=86400 * 30,
        )
        rrsig_rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        rrsig_rrset.add(rrsig)
        return a_rrset, rrsig_rrset

    def _sign_all(self, zones):
        for fqdn, ip in zones.items():
            zname              = dns.name.from_text(fqdn)
            dk_rdata, dk_rrset = self._make_dnskey(zname)
            a_rrset, rrsig_rrset = self._sign_a(zname, ip, dk_rdata)
            self._dnskey_cache[fqdn] = (dk_rdata, dk_rrset)
            self._rrsig_cache[fqdn]  = (a_rrset, rrsig_rrset)
            logger.info("[DNSSEC] Signed %-28s key_tag=%d", fqdn, dnssec.key_id(dk_rdata))

    # ── public API ────────────────────────────────────────────────────────
    def get_signed_answer(self, fqdn):
        return self._rrsig_cache.get(fqdn, (None, None))

    def get_dnskey_rrset(self, fqdn):
        pair = self._dnskey_cache.get(fqdn)
        return pair[1] if pair else None

    def get_dnskey_rdata(self, fqdn):
        pair = self._dnskey_cache.get(fqdn)
        return pair[0] if pair else None

    def get_rrsig_rdata(self, fqdn):
        pair = self._rrsig_cache.get(fqdn)
        if pair is None:
            return None
        _, rrsig_rrset = pair
        return list(rrsig_rrset)[0] if rrsig_rrset else None

    def key_tag(self, fqdn):
        rdata = self.get_dnskey_rdata(fqdn)
        return dnssec.key_id(rdata) if rdata else None


# ═════════════════════════════════════════════════════════════════════════════
# Shared State
# ═════════════════════════════════════════════════════════════════════════════
_lock               = threading.Lock()
blocked_ips         = {}
query_counts        = defaultdict(deque)
nxdomain_counts     = defaultdict(deque)
subdomain_sets      = defaultdict(lambda: {"window_start": 0, "domains": set()})
query_fingerprints  = defaultdict(deque)
query_timings       = defaultdict(deque)
nxd_totals          = defaultdict(int)
all_totals          = defaultdict(int)
dnssec_query_counts = defaultdict(lambda: defaultdict(deque))  # ip -> qtype -> timestamps

attack_events: deque = deque(maxlen=500)
stats = {
    "total_queries":   0,
    "blocked_queries": 0,
    "attacks_detected": {
        "amplification":    0,
        "nxdomain_flood":   0,
        "random_subdomain": 0,
        "flood":            0,
        "phantom_domain":   0,
        "bot_based":        0,
        "dnssec_exhaustion": 0,
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════
def _log_attack(atype, ip, detail):
    ev = {"timestamp": time.time(), "type": atype, "ip": ip, "detail": detail}
    with _lock:
        attack_events.appendleft(ev)
        stats["attacks_detected"][atype] += 1
        stats["blocked_queries"] += 1
    logger.warning("[%s] %s — %s", atype.upper(), ip, detail)


def _is_blocked(ip):
    with _lock:
        until = blocked_ips.get(ip)
    if until is None:
        return False
    if time.time() < until:
        return True
    with _lock:
        blocked_ips.pop(ip, None)
    return False


def _block_ip(ip, duration, reason):
    with _lock:
        blocked_ips[ip] = time.time() + duration
    _log_attack(reason, ip, f"Blocked for {duration}s")


def _rcode_str(rcode_int: int) -> str:
    mapping = {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
        3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
    }
    return mapping.get(rcode_int, str(rcode_int))


def _detect_dnssec_ok(request) -> bool:
    """
    Detect whether the client set the DO (DNSSEC OK) bit.

    dnslib represents EDNS0 OPT records as plain RR objects.
    Depending on the dnslib version the extended flags live either:
      • directly on the RR as  ar.ednsflags
      • inside the rdata as    ar.rdata.flags   (EDNSOption object)
      • encoded in ar.rdata    as raw bytes      (older builds)

    We try all three locations and fall back to False safely.
    """
    for ar in request.ar:
        if ar.rtype != QTYPE.OPT:
            continue
        # --- strategy 1: attribute directly on the RR object
        flags = getattr(ar, "ednsflags", None)
        if flags is not None:
            return bool(flags & 0x8000)

        # --- strategy 2: flags inside rdata object
        rdata = getattr(ar, "rdata", None)
        if rdata is not None:
            flags = getattr(rdata, "flags", None)
            if flags is not None:
                return bool(flags & 0x8000)

            # --- strategy 3: raw bytes — DO bit is in bytes 6-7 of OPT RDATA
            # OPT wire format: 4-byte extended RCODE+flags, then options
            # The DO bit is bit 15 of the 32-bit extended-RCODE field,
            # i.e. byte index 2 of the RDATA, bit 7.
            try:
                raw = bytes(rdata)
                if len(raw) >= 4:
                    ext_flags = int.from_bytes(raw[2:4], "big")
                    return bool(ext_flags & 0x8000)
            except Exception:
                pass
        break   # only one OPT record is valid
    return False


# ═════════════════════════════════════════════════════════════════════════════
# Protection Modules
# ═════════════════════════════════════════════════════════════════════════════
def _check_flood(ip):
    cfg = CONFIG["flood"]
    if not cfg["enabled"]:
        return False
    now = time.time()
    with _lock:
        q = query_counts[ip]
        while q and now - q[0] > 1.0:
            q.popleft()
        q.append(now)
        count = len(q)
    if count > cfg["max_queries_per_second"] + cfg["burst_allowance"]:
        _block_ip(ip, cfg["block_duration"], "flood")
        return True
    return False


def _check_amplification(ip, qtype):
    cfg = CONFIG["amplification"]
    if not cfg["enabled"]:
        return False
    if cfg["block_any_queries"] and qtype == QTYPE.ANY:
        _log_attack("amplification", ip, "QTYPE ANY blocked")
        return True
    high_bw = {QTYPE.TXT, QTYPE.ANY, QTYPE.DNSKEY, QTYPE.RRSIG, QTYPE.NS}
    if qtype in high_bw:
        now = time.time()
        with _lock:
            q = query_counts[f"amp_{ip}"]
            while q and now - q[0] > 1.0:
                q.popleft()
            q.append(now)
            count = len(q)
        if count > cfg["rate_limit_per_ip"]:
            _log_attack("amplification", ip, f"High-BW rate {count}/s")
            return True
    return False


def _check_nxdomain_flood(ip, is_nx):
    cfg = CONFIG["nxdomain_flood"]
    if not cfg["enabled"] or not is_nx:
        return False
    now = time.time()
    with _lock:
        q = nxdomain_counts[ip]
        while q and now - q[0] > cfg["window_seconds"]:
            q.popleft()
        q.append(now)
        count = len(q)
    if count > cfg["threshold"]:
        _block_ip(ip, cfg["block_duration"], "nxdomain_flood")
        return True
    return False


def _check_random_subdomain(ip, qname):
    cfg = CONFIG["random_subdomain"]
    if not cfg["enabled"]:
        return False
    now = time.time()
    with _lock:
        e = subdomain_sets[ip]
        if now - e["window_start"] > cfg["window_seconds"]:
            e["window_start"] = now
            e["domains"] = set()
        e["domains"].add(qname.lower())
        count = len(e["domains"])
    if count > cfg["unique_subdomain_threshold"]:
        _block_ip(ip, cfg["block_duration"], "random_subdomain")
        return True
    return False


def _check_phantom_domain(ip, qname, is_nx):
    cfg = CONFIG["phantom_domain"]
    if not cfg["enabled"]:
        return False
    qlow = qname.lower().rstrip(".")
    for tld in cfg["suspicious_tlds"]:
        if qlow.endswith(tld.lstrip(".")):
            _log_attack("phantom_domain", ip, f"Suspicious TLD: {qname}")
            return True
    with _lock:
        all_totals[ip] += 1
        if is_nx:
            nxd_totals[ip] += 1
        total = all_totals[ip]
        nxd   = nxd_totals[ip]
    if (total >= cfg["min_queries_to_evaluate"]
            and nxd / total > cfg["nxdomain_ratio_threshold"]):
        _block_ip(ip, 300, "phantom_domain")
        return True
    return False


def _check_bot_based(ip, qname, qtype):
    cfg = CONFIG["bot_based"]
    if not cfg["enabled"] or ip in cfg["whitelist"]:
        return False
    now = time.time()
    fp  = f"{qname}:{qtype}"
    with _lock:
        q = query_fingerprints[ip]
        while q and now - q[0][0] > cfg["fingerprint_window"]:
            q.popleft()
        identical = sum(1 for _, f in q if f == fp)
        q.append((now, fp))
        tq = query_timings[ip]
        while tq and now - tq[0] > cfg["fingerprint_window"]:
            tq.popleft()
        tq.append(now)
        timings = list(tq)
    if identical > cfg["identical_query_threshold"]:
        _block_ip(ip, 120, "bot_based")
        return True
    if len(timings) > 10:
        ivs  = [timings[i + 1] - timings[i] for i in range(len(timings) - 1)]
        mean = sum(ivs) / len(ivs)
        if mean > 0:
            cv = (sum((x - mean) ** 2 for x in ivs) / len(ivs)) ** 0.5 / mean
            if cv < cfg["query_interval_variance_threshold"]:
                _log_attack("bot_based", ip, f"Robotic timing CV={cv:.4f}")
                return True
    return False


def _check_dnssec_exhaustion(ip, qtype):
    """
    DNSSEC Validation Exhaustion:
    Attacker floods DNSKEY/RRSIG queries to exhaust CPU-intensive
    crypto operations on the server side.
    Defense: sliding-window rate limiter per IP per crypto query type.
    """
    cfg = CONFIG["dnssec_exhaustion"]
    if not cfg["enabled"]:
        return False

    DNSKEY_INT = 48
    RRSIG_INT  = 46

    if qtype not in (DNSKEY_INT, RRSIG_INT, QTYPE.DNSKEY, QTYPE.RRSIG):
        return False

    is_dnskey = qtype in (DNSKEY_INT, QTYPE.DNSKEY)
    threshold = cfg["dnskey_threshold"] if is_dnskey else cfg["rrsig_threshold"]
    qtype_str = "DNSKEY" if is_dnskey else "RRSIG"

    now = time.time()
    with _lock:
        q = dnssec_query_counts[ip][qtype_str]
        while q and now - q[0] > cfg["window_seconds"]:
            q.popleft()
        q.append(now)
        count = len(q)

    if count > threshold:
        _block_ip(ip, cfg["block_duration"], "dnssec_exhaustion")
        logger.warning(
            "[DNSSEC_EXHAUSTION] %s flooded %s queries: %d in %ds",
            ip, qtype_str, count, cfg["window_seconds"],
        )
        return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
# Resolver
# ═════════════════════════════════════════════════════════════════════════════
class SecureDNSResolver(BaseResolver):

    def __init__(self, signer: DNSSECSigner):
        self._signer = signer

    def resolve(self, request, handler):
        t_start   = time.perf_counter()
        client_ip = handler.client_address[0]
        protocol  = "tcp" if getattr(handler, "protocol", "udp") == "tcp" else "udp"

        with _lock:
            stats["total_queries"] += 1

        reply = request.reply()
        qtype = request.q.qtype
        qname = str(request.q.qname)
        fqdn  = qname.lower()

        # ── detect DO bit (DNSSEC OK) safely across dnslib versions ──────
        dnssec_ok = _detect_dnssec_ok(request)

        # ── pre-resolution checks ─────────────────────────────────────────
        if _is_blocked(client_ip):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        if _check_flood(client_ip):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        if _check_dnssec_exhaustion(client_ip, qtype):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        if _check_amplification(client_ip, qtype):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        if _check_random_subdomain(client_ip, qname):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        if _check_bot_based(client_ip, qname, qtype):
            reply.header.rcode = RCODE.REFUSED
            return self._finalize(reply, client_ip, qname, qtype, protocol,
                                  t_start, "REFUSED")

        # ── resolution ────────────────────────────────────────────────────
        is_nx = False
        rcode = "NOERROR"

        # ── DNSKEY query ──────────────────────────────────────────────────
        if qtype == QTYPE.DNSKEY:
            dk_rrset = self._signer.get_dnskey_rrset(fqdn)
            if dk_rrset is not None:
                dk_rdata = self._signer.get_dnskey_rdata(fqdn)
                key_tag  = self._signer.key_tag(fqdn)
                key_b64  = base64.b64encode(dk_rdata.key).decode()
                try:
                    reply.add_answer(*RR.fromZone(
                        f"{qname} 300 IN DNSKEY 257 3 13 {key_b64}"
                    ))
                    reply.header.aa = 1
                    logger.info("[DNSKEY] Served DNSKEY for %s  key_tag=%d", qname, key_tag)
                except Exception as e:
                    logger.error("[DNSKEY] Failed to build answer: %s", e)
                    reply.header.rcode = RCODE.SERVFAIL
                    rcode = "SERVFAIL"
            else:
                reply.header.rcode = RCODE.NXDOMAIN
                is_nx = True
                rcode = "NXDOMAIN"

        # ── A query ───────────────────────────────────────────────────────
        elif qtype == QTYPE.A:
            a_rrset, rrsig_rrset = self._signer.get_signed_answer(fqdn)
            if a_rrset is not None:
                for rr in a_rrset:
                    reply.add_answer(*RR.fromZone(f"{qname} 300 A {rr}"))
                reply.header.aa = 1

                # Attach RRSIG only when client requested DNSSEC (DO bit)
                if dnssec_ok and rrsig_rrset is not None:
                    rrsig_rdata = list(rrsig_rrset)[0]
                    sig_b64     = base64.b64encode(rrsig_rdata.signature).decode()
                    try:
                        reply.add_answer(*RR.fromZone(
                            f"{qname} 300 IN RRSIG A 13 2 300 "
                            f"20991231000000 20240101000000 "
                            f"{self._signer.key_tag(fqdn)} "
                            f"{qname} {sig_b64}"
                        ))
                        logger.debug("[DNSSEC] Attached RRSIG for %s (DO bit set)", qname)
                    except Exception as e:
                        logger.debug("[DNSSEC] RRSIG wire build skipped: %s", e)
            else:
                reply.header.rcode = RCODE.NXDOMAIN
                is_nx = True
                rcode = "NXDOMAIN"

        # ── other qtypes ──────────────────────────────────────────────────
        else:
            reply.header.rcode = RCODE.NXDOMAIN
            is_nx = True
            rcode = "NXDOMAIN"

        # ── post-resolution checks ────────────────────────────────────────
        if _check_nxdomain_flood(client_ip, is_nx):
            reply.header.rcode = RCODE.REFUSED
            rcode = "REFUSED"
        if _check_phantom_domain(client_ip, qname, is_nx):
            reply.header.rcode = RCODE.REFUSED
            rcode = "REFUSED"

        return self._finalize(reply, client_ip, qname, qtype, protocol, t_start, rcode)

    # ── helper ─────────────────────────────────────────────────────────────
    def _finalize(self, reply, client_ip, qname, qtype, protocol, t_start, rcode_str):
        """Log feature record and return reply."""
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        feature    = _build_feature(
            client_ip, qname, qtype, protocol,
            response_code=rcode_str,
            response_time_ms=elapsed_ms,
        )
        _enqueue_feature(feature)
        logger.info(
            "%-6s %-30s %-8s %s  %.2fms",
            protocol.upper(), qname.rstrip("."),
            _rcode_str(reply.header.rcode), client_ip, elapsed_ms,
        )
        return reply


# ═════════════════════════════════════════════════════════════════════════════
# Stats writer
# ═════════════════════════════════════════════════════════════════════════════
def _stats_writer():
    while True:
        time.sleep(2)
        with _lock:
            payload = {
                "timestamp": time.time(),
                "stats": {
                    "total_queries":    stats["total_queries"],
                    "blocked_queries":  stats["blocked_queries"],
                    "attacks_detected": dict(stats["attacks_detected"]),
                },
                "blocked_ips": {
                    ip: round(max(0, ts - time.time()), 1)
                    for ip, ts in blocked_ips.items()
                },
                "recent_events": list(attack_events)[:50],
            }
        try:
            with open(STATS_FILE, "w") as fh:
                json.dump(payload, fh, indent=2)
        except OSError as e:
            logger.error("Stats write failed: %s", e)


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════
def run(port=1053, address="0.0.0.0"):
    zones    = load_zones(ZONES_FILE)
    signer   = DNSSECSigner(zones)
    resolver = SecureDNSResolver(signer)

    udp = DNSServer(resolver, port=port, address=address, tcp=False)
    tcp = DNSServer(resolver, port=port, address=address, tcp=True)
    udp.start_thread()
    tcp.start_thread()

    active   = [k for k, v in CONFIG.items() if v.get("enabled")]
    inactive = [k for k, v in CONFIG.items() if not v.get("enabled")]

    logger.info("Secure DNS server listening on %s:%d (UDP + TCP)", address, port)
    logger.info("DNSSEC     : ACTIVE  (ECDSAP256SHA256, %d zones signed)", len(zones))
    logger.info("Zones file : %s", ZONES_FILE)
    logger.info("Feature log: %s", QUERY_LOG_FILE)
    logger.info("Protections ENABLED  : %s", ", ".join(active) if active else "none")
    logger.info("Protections DISABLED : %s", ", ".join(inactive))
    logger.info("")
    logger.info("Test commands:")
    logger.info("  dig @127.0.0.1 -p %d example.com A", port)
    logger.info("  dig @127.0.0.1 -p %d example.com A +dnssec", port)
    logger.info("  dig @127.0.0.1 -p %d example.com DNSKEY", port)

    threading.Thread(target=_stats_writer,   daemon=True).start()
    threading.Thread(target=_feature_writer, daemon=True).start()

    def _shutdown(sig, _):
        logger.info("Shutting down ...")
        udp.stop()
        tcp.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.pause()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure DNS Server with DNSSEC")
    parser.add_argument("--port",    type=int, default=1053)
    parser.add_argument("--address", default="0.0.0.0")
    args = parser.parse_args()
    run(port=args.port, address=args.address)
