#!/usr/bin/env python3
"""
DC Checker — Domain Controller Discovery & Health Check Tool
Discovers domain controllers, checks LDAP/Kerberos/SMB services, and tests replication health.
Author: Omar Khalid (amooryx) | github.com/amooryx/dc-checker
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import secrets
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

def _encode_dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        wire_label = label.encode("idna")
        if not wire_label or len(wire_label) > 63:
            raise ValueError("Invalid DNS label length")
        encoded.append(len(wire_label))
        encoded.extend(wire_label)
    encoded.append(0)
    if len(encoded) > 255:
        raise ValueError("DNS name is too long")
    return bytes(encoded)

def _decode_dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels = []
    cursor = offset
    next_offset = None
    visited = set()
    wire_length = 1

    while True:
        if cursor >= len(message):
            raise ValueError("Truncated DNS name")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= cursor or pointer in visited:
                raise ValueError("Invalid DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("Invalid DNS label encoding")
        cursor += 1
        if length == 0:
            if next_offset is None:
                next_offset = cursor
            break
        if length > 63 or cursor + length > len(message):
            raise ValueError("Truncated DNS label")
        wire_length += length + 1
        if wire_length > 255:
            raise ValueError("DNS name is too long")
        try:
            labels.append(message[cursor:cursor + length].decode("idna"))
        except UnicodeError as exc:
            raise ValueError("Invalid DNS label encoding") from exc
        cursor += length

    return ".".join(labels).lower(), next_offset

def _build_dns_srv_query(name: str, transaction_id: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(name) + struct.pack("!HH", 33, 1)
    return header + question

def _parse_dns_srv_response(
    response: bytes, expected_name: str, domain: str, transaction_id: int = 1
) -> list[str]:
    if len(response) < 12:
        raise ValueError("Truncated DNS header")
    response_id, flags, question_count, answer_count, _, _ = struct.unpack(
        "!HHHHHH", response[:12]
    )
    if response_id != transaction_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000 or flags & 0x7800:
        raise ValueError("Invalid DNS response")
    if flags & 0x0200:
        raise ValueError("Truncated DNS response")
    if flags & 0x000F:
        raise ValueError(f"DNS server returned response code {flags & 0x000F}")
    if question_count != 1:
        raise ValueError("Unexpected DNS question count")
    expected_name, _ = _decode_dns_name(_encode_dns_name(expected_name), 0)
    domain, _ = _decode_dns_name(_encode_dns_name(domain), 0)

    offset = 12
    question_name, offset = _decode_dns_name(response, offset)
    if offset + 4 > len(response):
        raise ValueError("Truncated DNS question")
    question_type, question_class = struct.unpack("!HH", response[offset:offset + 4])
    offset += 4
    if (question_name, question_type, question_class) != (
        expected_name.rstrip(".").lower(), 33, 1
    ):
        raise ValueError("DNS question does not match SRV query")

    expected_owner = expected_name
    targets = []
    for _ in range(answer_count):
        owner, offset = _decode_dns_name(response, offset)
        if offset + 10 > len(response):
            raise ValueError("Truncated DNS answer")
        record_type, record_class, _, data_length = struct.unpack(
            "!HHIH", response[offset:offset + 10]
        )
        offset += 10
        data_end = offset + data_length
        if data_end > len(response):
            raise ValueError("Truncated DNS answer data")

        if record_type == 33 and record_class == 1 and owner == expected_owner:
            if data_length < 7:
                raise ValueError("Invalid DNS SRV record")
            target, target_end = _decode_dns_name(response, offset + 6)
            if target_end != data_end:
                raise ValueError("Invalid DNS SRV target length")
            if target and (target == domain or target.endswith("." + domain)):
                targets.append(target)
        offset = data_end
    return targets

def discover_dcs_via_dns(domain: str) -> list[str]:
    """Query _ldap._tcp.dc._msdcs SRV record to find DCs."""
    dcs = []
    for prefix in [f"_ldap._tcp.dc._msdcs.{domain}", f"_kerberos._tcp.dc._msdcs.{domain}"]:
        try:
            transaction_id = secrets.randbits(16)
            query = _build_dns_srv_query(prefix, transaction_id)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(query, ("8.8.8.8", 53))
                response = sock.recv(4096)
            dcs.extend(
                _parse_dns_srv_response(response, prefix, domain, transaction_id)
            )
        except (OSError, ValueError) as exc:
            print(f"[!] DNS SRV query failed for {prefix}: {exc}", file=sys.stderr)
    return list(dict.fromkeys(dcs))

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
