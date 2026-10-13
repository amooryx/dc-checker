import io
import struct
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import dc_checker


def srv_response(query, target="dc1.example.com"):
    question = query[12:]
    transaction_id = struct.unpack("!H", query[:2])[0]
    record_data = struct.pack("!HHH", 0, 100, 389) + dc_checker._encode_dns_name(target)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 33, 1, 60, len(record_data))
        + record_data
    )
    return (
        struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )


class DnsSrvParsingTests(unittest.TestCase):
    def test_builds_valid_srv_query(self):
        query = dc_checker._build_dns_srv_query("_ldap._tcp.example.com")

        self.assertEqual(struct.unpack("!HHHHHH", query[:12]), (1, 0x0100, 1, 0, 0, 0))
        self.assertEqual(query[-4:], struct.pack("!HH", 33, 1))

    def test_parses_compressed_srv_owner_and_fqdn_target(self):
        name = "_ldap._tcp.dc._msdcs.example.com"
        response = srv_response(dc_checker._build_dns_srv_query(name))

        self.assertEqual(
            dc_checker._parse_dns_srv_response(response, name, "example.com"),
            ["dc1.example.com"],
        )

    def test_ignores_srv_targets_outside_queried_domain(self):
        name = "_ldap._tcp.dc._msdcs.example.com"
        response = srv_response(
            dc_checker._build_dns_srv_query(name), "dc1.unrelated.test"
        )

        self.assertEqual(
            dc_checker._parse_dns_srv_response(response, name, "example.com"), []
        )

    def test_rejects_mismatched_transaction_id(self):
        name = "_ldap._tcp.dc._msdcs.example.com"
        response = bytearray(srv_response(dc_checker._build_dns_srv_query(name)))
        response[0:2] = b"\x00\x02"

        with self.assertRaisesRegex(ValueError, "transaction ID"):
            dc_checker._parse_dns_srv_response(bytes(response), name, "example.com")

    def test_rejects_truncated_compression_pointer(self):
        name = "_ldap._tcp.dc._msdcs.example.com"
        response = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        response += b"\xc0"

        with self.assertRaisesRegex(ValueError, "compression pointer"):
            dc_checker._parse_dns_srv_response(response, name, "example.com")

    def test_discovery_uses_mocked_udp_responses(self):
        sent_queries = []

        class MockSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendto(self, query, address):
                sent_queries.append((query, address))

            def recv(self, size):
                return srv_response(sent_queries[-1][0])

        with patch.object(dc_checker.socket, "socket", return_value=MockSocket()):
            discovered = dc_checker.discover_dcs_via_dns("example.com")

        self.assertEqual(discovered, ["dc1.example.com"])
        self.assertEqual(len(sent_queries), 2)
        self.assertTrue(all(address == ("8.8.8.8", 53) for _, address in sent_queries))

    def test_discovery_reports_malformed_responses(self):
        class MockSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendto(self, query, address):
                pass

            def recv(self, size):
                return b""

        errors = io.StringIO()
        with patch.object(dc_checker.socket, "socket", return_value=MockSocket()):
            with redirect_stderr(errors):
                discovered = dc_checker.discover_dcs_via_dns("example.com")

        self.assertEqual(discovered, [])
        self.assertEqual(errors.getvalue().count("Truncated DNS header"), 2)


if __name__ == "__main__":
    unittest.main()
