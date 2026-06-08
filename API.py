#!/usr/bin/env python3
"""
SDN Manager - Ryu Controller Client
Works with:
  ryu-manager --wsapi-port 8082
    ryu.app.simple_switch_13
    ryu.app.ofctl_rest
    ryu.app.rest_topology
    ryu.app.gui_topology.gui_topology
    ryu.app.rest_firewall
"""

import requests
import sys
from collections import defaultdict

BASE_URL = "http://localhost:8082"


def banner():
    print("=" * 60)
    print("  SDN Manager — Ryu Controller Client")
    print(f"  Target : {BASE_URL}")
    print("=" * 60)


# ── helpers ────────────────────────────────────────────────────
def get(path):
    """GET request, returns parsed JSON or None on any error."""
    try:
        r = requests.get(f"{BASE_URL}{path}", timeout=5)
        if r.status_code == 200:
            return r.json()
        print(f"  [!] GET {path} → HTTP {r.status_code}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"\n[!] FATAL: Cannot reach Ryu at {BASE_URL}")
        print("    Is ryu-manager running with --wsapi-port 8082 ?")
        sys.exit(1)
    except Exception as e:
        print(f"  [!] GET {path} → {e}")
        return None


def put(path):
    """PUT request, returns (status_code, text)."""
    try:
        r = requests.put(f"{BASE_URL}{path}",
                         headers={"Content-Type": "application/json"},
                         timeout=5)
        return r.status_code, r.text.strip()
    except requests.exceptions.ConnectionError:
        return 0, "connection error"
    except Exception as e:
        return 0, str(e)


# ── STEP 1 : get switches ──────────────────────────────────────
def get_switches():
    print("\n[1] Discovering switches ...")

    # primary: rest_topology
    data = get("/v1.0/topology/switches")
    if data is not None:
        dpids = [sw["dpid"] for sw in data]
        if dpids:
            print(f"    Source : /v1.0/topology/switches")
            print(f"    Found  : {len(dpids)} switch(es)")
            return dpids

    # fallback: ofctl_rest
    data = get("/stats/switches")
    if data is not None:
        # returns a list of integer datapath IDs
        dpids = [format(d, '016x') for d in data]
        if dpids:
            print(f"    Source : /stats/switches  (fallback)")
            print(f"    Found  : {len(dpids)} switch(es)")
            return dpids

    print("[!] No switches found. Is Mininet running and connected?")
    sys.exit(1)


# ── STEP 2 : map switches → IPv4 hosts ────────────────────────
def get_host_ip_map(dpids):
    """Returns dict  dpid → set of IPv4 strings."""
    ip_map = defaultdict(set)

    # ── 2a: rest_topology hosts ──
    print("\n[2] Discovering hosts ...")
    data = get("/v1.0/topology/hosts")
    if data:
        for host in data:
            ipv4_list = host.get("ipv4", [])
            port      = host.get("port", {})
            dpid      = port.get("dpid", "")
            for ip in ipv4_list:
                if ip and not ip.startswith("127."):
                    ip_map[dpid].add(ip)
        total = sum(len(v) for v in ip_map.values())
        if total:
            print(f"    Source : /v1.0/topology/hosts  → {total} IP(s) found")
            return ip_map

    print("    /v1.0/topology/hosts returned nothing — mining flow tables ...")

    # ── 2b: flow table mining ──
    for dpid in dpids:
        dp_int = int(dpid, 16)
        data = get(f"/stats/flow/{dp_int}")
        if not data:
            continue
        flows = data.get(str(dp_int), [])
        for flow in flows:
            match = flow.get("match", {})
            for field in ("ipv4_src", "ipv4_dst", "nw_src", "nw_dst"):
                ip = match.get(field, "")
                # strip prefix length if present  e.g. "10.0.0.1/32"
                ip = ip.split("/")[0] if ip else ""
                if ip and not ip.startswith("127.") and not ip.startswith("0."):
                    ip_map[dpid].add(ip)

    total = sum(len(v) for v in ip_map.values())
    if total:
        print(f"    Source : /stats/flow  → {total} IP(s) found")
    else:
        print("    [~] No host IPs found. Run 'pingall' in Mininet first,")
        print("        then re-run this script.")

    return ip_map


# ── STEP 3 : enable firewall on every switch ───────────────────
def enable_firewalls(dpids):
    print("\n[3] Enabling firewall on all switches ...")
    results = {}
    for dpid in dpids:
        code, body = put(f"/firewall/module/enable/{dpid}")
        if code == 200:
            print(f"    [+] {dpid}  →  ENABLED  ✓")
            results[dpid] = "enabled"
        else:
            print(f"    [!] {dpid}  →  HTTP {code}  {body}")
            results[dpid] = f"FAILED ({code})"
    return results


# ── STEP 4 : print summary ─────────────────────────────────────
def print_summary(dpids, ip_map, fw_results):
    print("\n" + "=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    print(f"  Switches found : {len(dpids)}\n")

    all_ips = []
    for dpid in dpids:
        ips = sorted(ip_map.get(dpid, []))
        fw  = fw_results.get(dpid, "unknown")
        fw_icon = "✓" if fw == "enabled" else "✗"

        print(f"  ┌─ Switch  : {dpid}")
        print(f"  │  Firewall: [{fw_icon}] {fw}")
        if ips:
            for ip in ips:
                print(f"  │  Host IP : {ip}")
                all_ips.append(ip)
        else:
            print(f"  │  Host IP : (none detected)")
        print(f"  └{'─'*50}")

    print("\n  ALL IPv4 ADDRESSES DISCOVERED:")
    if all_ips:
        for ip in sorted(set(all_ips)):
            print(f"    →  {ip}")
    else:
        print("    (none — run 'pingall' in Mininet, then retry)")

    print("\n" + "=" * 60)
    print("  Done.")
    print("=" * 60)


# ── main ───────────────────────────────────────────────────────
def main():
    banner()
    dpids      = get_switches()
    ip_map     = get_host_ip_map(dpids)
    fw_results = enable_firewalls(dpids)
    print_summary(dpids, ip_map, fw_results)


if __name__ == "__main__":
    main()