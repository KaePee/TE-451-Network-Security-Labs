"""
A small, deterministic pcap writer: just enough Ethernet / IPv4 / TCP / UDP /
DNS to build realistic per-student captures that Wireshark dissects cleanly
(valid checksums, proper TCP handshakes and sequence numbers, so "Follow TCP
Stream" and Statistics -> Conversations work).

Frames are not padded to the 60-byte Ethernet minimum, matching what a
capture on the sending host looks like, so Wireshark's byte counts equal
sum(len(frame)), which the graders rely on.
"""

import random
import socket
import struct
from dataclasses import dataclass, field

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS = 1448


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip(addr: str) -> bytes:
    return socket.inet_aton(addr)


def _mac(addr: str) -> bytes:
    return bytes.fromhex(addr.replace(":", ""))


@dataclass
class Host:
    ip: str
    mac: str          # for off-LAN hosts, the router's MAC (that's what's on the wire)
    _ident: int = 0

    def next_ident(self) -> int:
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident


def random_mac(rng: random.Random) -> str:
    # Locally administered, unicast.
    first = (rng.randrange(256) | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in [first] + [rng.randrange(256) for _ in range(5)])


def ethernet(src: Host, dst: Host, payload: bytes, ethertype: int = 0x0800) -> bytes:
    return _mac(dst.mac) + _mac(src.mac) + struct.pack("!H", ethertype) + payload


def ipv4(src: Host, dst: Host, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), src.next_ident(),
                         0x4000, ttl, proto, 0, _ip(src.ip), _ip(dst.ip))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _transport_checksum(src: Host, dst: Host, proto: int, segment: bytes) -> int:
    pseudo = _ip(src.ip) + _ip(dst.ip) + struct.pack("!BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


def tcp(src: Host, dst: Host, sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"", window: int = 64240) -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                         5 << 4, flags, window, 0, 0)
    csum = _transport_checksum(src, dst, 6, header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return ethernet(src, dst, ipv4(src, dst, 6, header + payload))


def udp(src: Host, dst: Host, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = _transport_checksum(src, dst, 17, header + payload) or 0xFFFF
    header = header[:6] + struct.pack("!H", csum)
    return ethernet(src, dst, ipv4(src, dst, 17, header + payload))


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(qid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + b"\0\x01\0\x01"


def dns_response(qid: int, name: str, addr: str) -> bytes:
    question = _dns_name(name) + b"\0\x01\0\x01"
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + _ip(addr)
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


@dataclass
class _Packet:
    ts: float
    order: int
    frame: bytes
    tag: str | None


@dataclass
class Capture:
    packets: list[_Packet] = field(default_factory=list)

    def add(self, ts: float, frame: bytes, tag: str | None = None) -> None:
        self.packets.append(_Packet(ts, len(self.packets), frame, tag))

    def ordered(self) -> list[_Packet]:
        return sorted(self.packets, key=lambda p: (p.ts, p.order))

    def frame_number(self, tag: str) -> int:
        """1-based, as Wireshark numbers frames."""
        for i, p in enumerate(self.ordered(), start=1):
            if p.tag == tag:
                return i
        raise KeyError(tag)

    def _between(self, a: str, b: str):
        pair = {_ip(a), _ip(b)}
        for p in self.packets:
            ip = p.frame[14:34]
            if p.frame[12:14] == b"\x08\x00" and {ip[12:16], ip[16:20]} == pair:
                yield p

    def bytes_between(self, a: str, b: str) -> int:
        return sum(len(p.frame) for p in self._between(a, b))

    def packets_between(self, a: str, b: str) -> int:
        return sum(1 for _ in self._between(a, b))

    def to_pcap(self) -> bytes:
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for p in self.ordered():
            sec = int(p.ts)
            usec = int(round((p.ts - sec) * 1_000_000))
            if usec == 1_000_000:
                sec, usec = sec + 1, 0
            out.append(struct.pack("<IIII", sec, usec, len(p.frame), len(p.frame)) + p.frame)
        return b"".join(out)


class TcpConversation:
    """One TCP connection with its own clock. Interleaving between
    conversations happens when the Capture sorts by timestamp."""

    def __init__(self, cap: Capture, rng: random.Random, client: Host, server: Host,
                 sport: int, dport: int, start: float):
        self.cap, self.rng = cap, rng
        self.client, self.server = client, server
        self.sport, self.dport = sport, dport
        self.t = start
        self.rtt = rng.uniform(0.004, 0.035)
        self.cseq = rng.getrandbits(32)
        self.sseq = rng.getrandbits(32)

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"", tag=None):
        if from_client:
            frame = tcp(self.client, self.server, self.sport, self.dport, self.cseq,
                        self.sseq, flags, payload)
        else:
            frame = tcp(self.server, self.client, self.dport, self.sport, self.sseq,
                        self.cseq, flags, payload)
        self.cap.add(self.t, frame, tag)

    def _step(self, scale: float = 0.5):
        self.t += self.rtt * scale * self.rng.uniform(0.8, 1.2)

    def open(self) -> "TcpConversation":
        self._emit(True, SYN)
        self.cseq += 1
        self._step()
        self._emit(False, SYN | ACK)
        self.sseq += 1
        self._step()
        self._emit(True, ACK)
        self._step(0.2)
        return self

    def send(self, from_client: bool, data: bytes, tag: str | None = None) -> None:
        for i in range(0, len(data), MSS):
            chunk = data[i:i + MSS]
            self._emit(from_client, PSH | ACK, chunk, tag if i == 0 else None)
            if from_client:
                self.cseq += len(chunk)
            else:
                self.sseq += len(chunk)
            self._step()
            self._emit(not from_client, ACK)
            self._step(0.05)

    def wait(self, seconds: float) -> None:
        self.t += seconds

    def close(self) -> None:
        self._emit(True, FIN | ACK)
        self.cseq += 1
        self._step()
        self._emit(False, FIN | ACK)
        self.sseq += 1
        self._step()
        self._emit(True, ACK)
