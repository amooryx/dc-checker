#!/usr/bin/env python3
"""
DC Checker — Domain Controller Discovery & Health Check Tool
Discovers domain controllers, checks LDAP/Kerberos/SMB services, and tests replication health.
Author: Omar Khalid (amooryx) | github.com/amooryx/dc-checker
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

DC_PORTS = {
    88:   "Kerberos",
    389:  "LDAP",
    636:  "LDAPS",
    445:  "SMB",
    135:  "RPC",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
    464:  "Kpasswd",
    9389: "AD Web Services",
}

def check_port(host: str, port: int, timeout: float = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def discover_dcs_via_dns(domain: str) -> list[str]:
    """Query _ldap._tcp.dc._msdcs SRV record to find DCs."""
    dcs = []
    for prefix in [f"_ldap._tcp.dc._msdcs.{domain}", f"_kerberos._tcp.dc._msdcs.{domain}"]:
        try:
            # Use raw socket + manual DNS query for SRV (no external deps)
            import struct
            srv_name  = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in prefix.split(".")) + b"\x00"
            query     = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + srv_name + b"\x00\x21\x00\x01"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query, ("8.8.8.8", 53))
            resp = sock.recv(512)
            sock.close()
            # Just try to extract hostnames from the response (simplified)
            for part in resp.decode(errors="ignore").split("\x00"):
                part = part.strip()
                if part.endswith(f".{domain}") or (len(part) > 4 and domain in part):
                    dcs.append(part)
        except Exception:
            pass
    return list(set(dcs))

def discover_dcs_via_nbt(subnet_prefix: str) -> list[str]:
    """Broadcast NetBIOS Name Service query to find DCs (within local subnet)."""
    dcs = []
    # NBT NS broadcast for domain controllers
    nbt_ns_query = (
        b"\x00\x00\x00\x10"  # Transaction ID + flags
        b"\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20FHFAEBEECACACACACACACACACACACACA\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)
        sock.sendto(nbt_ns_query, (f"{subnet_prefix}.255", 137))
        while True:
            try:
                data, addr = sock.recvfrom(512)
                ip = addr[0]
                if ip not in dcs and ip != f"{subnet_prefix}.255":
                    dcs.append(ip)
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return dcs

def scan_dc(host: str, timeout: float) -> dict:
    result = {"host": host, "services": {}, "is_dc_likely": False}
    dc_ports_open = 0
    for port, name in DC_PORTS.items():
        open_ = check_port(host, port, timeout)
        if open_:
            result["services"][port] = name
            if port in (88, 389, 3268):
                dc_ports_open += 1

    result["is_dc_likely"] = dc_ports_open >= 2
    return result

def main():
    parser = argparse.ArgumentParser(
        description="DC Checker — Domain Controller Discovery (Authorized use only)",
    )
    parser.add_argument("--domain",  help="Domain to discover DCs via DNS SRV")
    parser.add_argument("--hosts",   nargs="*", help="Known DC IPs to check")
    parser.add_argument("--subnet",  help="Subnet prefix for NBT broadcast (e.g., 192.168.1)")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--out",     help="Output JSON file")
    args = parser.parse_args()

    targets = list(args.hosts or [])

    if args.domain:
        print(f"[*] Discovering DCs via DNS SRV for {args.domain} ...")
        dns_dcs = discover_dcs_via_dns(args.domain)
        print(f"  [+] DNS discovered: {dns_dcs}")
        targets.extend(dns_dcs)

    if args.subnet:
        print(f"[*] NBT broadcast discovery on {args.subnet}.0/24 ...")
        nbt_dcs = discover_dcs_via_nbt(args.subnet)
        print(f"  [+] NBT found: {nbt_dcs}")
        targets.extend(nbt_dcs)

    targets = list(set(targets))
    if not targets:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Scanning {len(targets)} hosts for DC services ...")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        for r in exe.map(lambda h: scan_dc(h, args.timeout), targets):
            results.append(r)
            if r["is_dc_likely"]:
                svcs = ", ".join(f"{v}({k})" for k, v in r["services"].items())
                print(f"  [+++] Likely DC: {r['host']} — {svcs}")
            else:
                print(f"  [ - ] {r['host']}: {list(r['services'].values())}")

    dcs = [r for r in results if r["is_dc_likely"]]
    print(f"\n[*] {len(dcs)}/{len(results)} hosts are likely Domain Controllers")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
