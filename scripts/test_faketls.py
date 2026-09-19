#!/usr/bin/env python3
"""Offline checks for FakeTLS layout and archive retention. No live proxies."""

from __future__ import annotations

import hmac
import hashlib
import socket
import struct
import threading
import unittest
from datetime import datetime, timezone

import faketls
import build_feeds as feeds


class FakeTlsLayoutTest(unittest.TestCase):
    def test_hello_is_517_and_digest_at_11(self) -> None:
        session = bytes((3,) * 32)
        share = bytes((4,) * 32)
        hello = faketls.build_client_hello("sberbank.ru", bytes(32), session, share)
        self.assertEqual(517, len(hello))
        self.assertEqual(0x16, hello[0])
        self.assertEqual(bytes(32), hello[faketls.DIGEST_POS : faketls.DIGEST_POS + 32])

    def test_client_random_is_hmac_xor_timestamp(self) -> None:
        key = bytes(range(16))
        session = bytes((3,) * 32)
        share = bytes((4,) * 32)
        ts = 1_700_000_000
        signed, random_field = faketls.sign_client_hello(
            "sberbank.ru", key, ts, session, share
        )
        unsigned = faketls.build_client_hello("sberbank.ru", bytes(32), session, share)
        digest = hmac.new(key, unsigned, hashlib.sha256).digest()
        expected = bytearray(digest)
        ts_bytes = struct.pack("<I", ts)
        for i in range(4):
            expected[28 + i] ^= ts_bytes[i]
        self.assertEqual(bytes(expected), random_field)
        self.assertEqual(bytes(expected), signed[11:43])

    def test_server_digest(self) -> None:
        key = bytes((i * 3) % 256 for i in range(16))
        client_random = bytes((9,) * 32)
        packet = bytearray((7,) * 80)
        zeroed = bytearray(packet)
        zeroed[11:43] = bytes(32)
        digest = hmac.new(key, client_random + bytes(zeroed), hashlib.sha256).digest()
        packet[11:43] = digest
        self.assertTrue(faketls.verify_server_digest(key, client_random, bytes(packet)))
        packet[12] ^= 1
        self.assertFalse(faketls.verify_server_digest(key, client_random, bytes(packet)))

    def test_probe_hmac_against_local_server(self) -> None:
        key = bytes(range(16))
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve() -> None:
            conn, _ = server.accept()
            with conn:
                data = b""
                while len(data) < 517:
                    chunk = conn.recv(517 - len(data))
                    if not chunk:
                        return
                    data += chunk
                client_random = data[11:43]
                payload = bytearray(75)
                payload[0] = 0x02
                header = bytes((0x16, 0x03, 0x03)) + struct.pack(">H", len(payload))
                flight = bytearray(header + bytes(payload))
                zeroed = bytearray(flight)
                zeroed[11:43] = bytes(32)
                digest = hmac.new(key, client_random + bytes(zeroed), hashlib.sha256).digest()
                flight[11:43] = digest
                conn.sendall(bytes(flight))

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(faketls.probe_hmac("127.0.0.1", port, key, "vk.com", timeout=2.0))
        server.close()


class ArchiveRetentionTest(unittest.TestCase):
    def test_windows(self) -> None:
        self.assertEqual(
            [feeds.retention(x) for x in (0, 30, 31, 60, 61.9, 62, 90, 91.9, 92)],
            ["daily", "daily", "hold", "far", "far", "hold", "far", "far", "drop"],
        )

    def test_last_ok_keeps_hot(self) -> None:
        now = datetime(2026, 9, 19, tzinfo=timezone.utc)
        entry = {
            "last_seen": "2026-06-01T00:00:00Z",
            "last_ok": "2026-09-18T00:00:00Z",
        }
        iso = feeds.evidence_iso(entry)
        age = (now - feeds.parse_stamp(iso)).total_seconds() / 86400
        self.assertEqual("daily", feeds.retention(age))


if __name__ == "__main__":
    unittest.main()
