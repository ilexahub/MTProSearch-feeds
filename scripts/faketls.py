#!/usr/bin/env python3
"""FakeTLS ClientHello / ServerHello HMAC, same layout as MTProSearchSrc FakeTls.kt."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import socket
import struct
import time

DIGEST_LEN = 32
DIGEST_POS = 11
TLS_VERS = bytes((0x03, 0x03))
CIPHER_SUITES = bytes(
    (
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xC0, 0x2B, 0xC0, 0x2F,
        0xC0, 0x2C, 0xC0, 0x30, 0xCC, 0xA9, 0xCC, 0xA8, 0xC0, 0x13, 0xC0, 0x14,
        0x00, 0x9C, 0x00, 0x9D, 0x00, 0x2F, 0x00, 0x35,
    )
)
CHECK_TIMEOUT_SEC = 5.0
MAX_FLIGHT = 4096


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _sni_extension(domain: str) -> bytes:
    sni = domain.encode("ascii")
    inner = b"\x00" + _u16(len(sni)) + sni
    listed = _u16(len(inner)) + inner
    return b"\x00\x00" + _u16(len(listed)) + listed


def _alpn_extension() -> bytes:
    alpn = b"\x02h2\x08http/1.1"
    inner = _u16(len(alpn)) + alpn
    return b"\x00\x10" + _u16(len(inner)) + inner


def _sig_algs_extension() -> bytes:
    algs = bytes(
        (
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
            0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        )
    )
    inner = _u16(len(algs)) + algs
    return b"\x00\x0D" + _u16(len(inner)) + inner


def _key_share_extension(pub: bytes) -> bytes:
    entry = b"\x00\x1D" + _u16(len(pub)) + pub
    listed = _u16(len(entry)) + entry
    return b"\x00\x33" + _u16(len(listed)) + listed


def build_client_hello(
    sni: str,
    random_field: bytes,
    session_id: bytes,
    key_share: bytes,
) -> bytes:
    if len(random_field) != DIGEST_LEN or len(session_id) != 32 or len(key_share) != 32:
        raise ValueError("hello field sizes")
    extensions_without_pad = (
        _sni_extension(sni)
        + bytes((0x00, 0x17, 0x00, 0x00))
        + bytes((0xFF, 0x01, 0x00, 0x01, 0x00))
        + bytes((0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18))
        + bytes((0x00, 0x0B, 0x00, 0x02, 0x01, 0x00))
        + bytes((0x00, 0x23, 0x00, 0x00))
        + _alpn_extension()
        + bytes((0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00))
        + _sig_algs_extension()
        + bytes((0x00, 0x12, 0x00, 0x00))
        + _key_share_extension(key_share)
        + bytes((0x00, 0x2D, 0x00, 0x02, 0x01, 0x01))
        + bytes((0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03))
        + bytes((0x00, 0x1B, 0x00, 0x03, 0x02, 0x00, 0x02))
    )
    current_total = 5 + 4 + 2 + 32 + 1 + 32 + 2 + len(CIPHER_SUITES) + 2 + 2 + len(extensions_without_pad)
    pad_needed = max(0, 517 - current_total - 4)
    padding_ext = bytes((0x00, 0x15)) + _u16(pad_needed) + bytes(pad_needed)
    extensions = extensions_without_pad + padding_ext
    body = (
        TLS_VERS
        + random_field
        + bytes((len(session_id),))
        + session_id
        + _u16(len(CIPHER_SUITES))
        + CIPHER_SUITES
        + bytes((0x01, 0x00))
        + _u16(len(extensions))
        + extensions
    )
    handshake = bytes((0x01,)) + _u24(len(body)) + body
    return bytes((0x16, 0x03, 0x01)) + _u16(len(handshake)) + handshake


def sign_client_hello(
    sni: str,
    secret_key: bytes,
    timestamp_sec: int,
    session_id: bytes | None = None,
    key_share: bytes | None = None,
) -> tuple[bytes, bytes]:
    session_id = session_id if session_id is not None else secrets.token_bytes(32)
    key_share = key_share if key_share is not None else secrets.token_bytes(32)
    unsigned = build_client_hello(sni, bytes(DIGEST_LEN), session_id, key_share)
    digest = hmac.new(secret_key, unsigned, hashlib.sha256).digest()
    ts = struct.pack("<I", timestamp_sec & 0xFFFFFFFF)
    random_field = bytearray(digest)
    for i in range(4):
        random_field[DIGEST_LEN - 4 + i] ^= ts[i]
    signed = bytearray(unsigned)
    signed[DIGEST_POS : DIGEST_POS + DIGEST_LEN] = random_field
    return bytes(signed), bytes(random_field)


def verify_server_digest(secret_key: bytes, client_random: bytes, server_packet: bytes) -> bool:
    if len(server_packet) < DIGEST_POS + DIGEST_LEN:
        return False
    server_digest = server_packet[DIGEST_POS : DIGEST_POS + DIGEST_LEN]
    zeroed = bytearray(server_packet)
    zeroed[DIGEST_POS : DIGEST_POS + DIGEST_LEN] = b"\x00" * DIGEST_LEN
    expected = hmac.new(secret_key, client_random + bytes(zeroed), hashlib.sha256).digest()
    return hmac.compare_digest(expected, server_digest)


def _read_record(sock: socket.socket) -> bytes | None:
    header = _recv_exact(sock, 5)
    if header is None or len(header) < 5:
        return None
    length = int.from_bytes(header[3:5], "big")
    if length <= 0 or length > 16_384:
        return None
    payload = _recv_exact(sock, length)
    if payload is None or len(payload) != length:
        return None
    return header + payload


def _recv_exact(sock: socket.socket, size: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def probe_hmac(host: str, port: int, secret_key: bytes, sni: str, timeout: float = CHECK_TIMEOUT_SEC) -> bool:
    """TCP + FakeTLS HMAC. Not req_pq. GitHub's network ≠ a phone in RU."""
    target = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    record, client_random = sign_client_hello(sni, secret_key, int(time.time()))
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(record)
            first = _read_record(sock)
            if first is None or first[0] != 0x16 or len(first) < 6 or first[5] != 0x02:
                return False
            flight = bytearray(first)
            if verify_server_digest(secret_key, client_random, bytes(flight)):
                return True
            while len(flight) < MAX_FLIGHT:
                nxt = _read_record(sock)
                if nxt is None:
                    return False
                flight.extend(nxt)
                if verify_server_digest(secret_key, client_random, bytes(flight)):
                    return True
    except OSError:
        return False
    return False
