"""Minimal, deterministic TLS handshake records for Lab 8, carried over the
TcpConversation in pcap.py. Just enough of a ClientHello / ServerHello that
Wireshark dissects the SNI and the negotiated cipher suite cleanly; the
application data is opaque, like real encrypted traffic.
"""

import random
import struct

from . import pcap

# code -> (name, gives_forward_secrecy, modern). Mix of good and legacy suites.
CIPHER_SUITES = {
    0x1301: ("TLS_AES_128_GCM_SHA256", True, True),
    0x1302: ("TLS_AES_256_GCM_SHA384", True, True),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", True, True),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", True, True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", True, True),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", False, False),      # static RSA: no FS
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", False, False),         # static RSA + CBC
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", False, False),        # legacy, weak
}


def _vec(data: bytes, lenbytes: int) -> bytes:
    return len(data).to_bytes(lenbytes, "big") + data


def client_hello(rng: random.Random, sni: str, suites: list[int]) -> bytes:
    body = b"\x03\x03" + bytes(rng.randrange(256) for _ in range(32))     # TLS 1.2 + random
    body += _vec(b"", 1)                                                  # empty session id
    body += _vec(b"".join(struct.pack("!H", s) for s in suites), 2)       # cipher suites
    body += _vec(b"\x00", 1)                                              # compression: null
    server_name = _vec(b"\x00" + _vec(sni.encode(), 2), 2)                # server_name_list
    ext_sni = b"\x00\x00" + _vec(server_name, 2)
    body += _vec(ext_sni, 2)                                              # extensions
    handshake = b"\x01" + _vec(body, 3)                                   # ClientHello
    return b"\x16\x03\x01" + _vec(handshake, 2)                           # TLS record


def server_hello(rng: random.Random, suite: int) -> bytes:
    body = b"\x03\x03" + bytes(rng.randrange(256) for _ in range(32))
    body += _vec(b"", 1) + struct.pack("!H", suite) + b"\x00" + _vec(b"", 2)
    handshake = b"\x02" + _vec(body, 3)                                   # ServerHello
    return b"\x16\x03\x03" + _vec(handshake, 2)


def app_data(rng: random.Random, length: int) -> bytes:
    return b"\x17\x03\x03" + _vec(bytes(rng.randrange(256) for _ in range(length)), 2)


def build_handshake(rng, client, server, sni, offered, chosen, *, start=1.0, sport=51000):
    """A full TCP+TLS handshake on 443, added to a fresh Capture; returns it."""
    cap = pcap.Capture()
    conv = pcap.TcpConversation(cap, rng, client, server, sport, 443, start).open()
    conv.send(True, client_hello(rng, sni, offered), tag="clienthello")
    conv.send(False, server_hello(rng, chosen), tag="serverhello")
    conv.send(False, app_data(rng, rng.randrange(600, 1400)))
    conv.send(True, app_data(rng, rng.randrange(200, 600)))
    conv.close()
    return cap
