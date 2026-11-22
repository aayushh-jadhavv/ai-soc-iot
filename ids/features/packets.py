"""One byte parser for PCAP replay and libpcap callbacks. Times are integer ns.

No checksum validation (capture offload can change checksums), reassembly, TCP
stream reconstruction or retransmission removal is performed by v1.
"""

from dataclasses import dataclass
from pathlib import Path
import hashlib
import ipaddress
import struct

SECOND = 1_000_000_000


@dataclass(frozen=True, slots=True)
class RawPacket:
    time_ns: int
    data: bytes
    original_length: int
    linktype: int
    interface: str
    source_id: str = "live"
    number: int = 0

    def __post_init__(self):
        if type(self.time_ns) is not int or self.time_ns < 0:
            raise ValueError("Packet time must be nonnegative integer nanoseconds")
        if self.original_length < len(self.data) or not self.interface:
            raise ValueError("Invalid packet length/interface")


@dataclass(frozen=True, slots=True)
class PacketRecord:
    time_ns: int
    interface: str
    linktype: int
    source_id: str
    number: int
    src: str | None = None
    dst: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    protocol: str | None = None
    sport: int | None = None
    dport: int | None = None
    ip_length: int = 0
    tcp_flags: int = 0
    issues: tuple[str, ...] = ()
    registry_only: bool = False
    capture_kind: int | None = None
    ttl: int | None = None
    view_fingerprint: bytes | None = None

    @property
    def supported(self):
        return not self.issues and not self.registry_only and self.protocol in {"tcp", "udp", "icmp"}

    @property
    def tuple_key(self):
        return (self.protocol, self.src, self.sport, self.dst, self.dport)


def canonical_tuple(key):
    proto, src, sport, dst, dport = key
    left, right = (src, str(sport)), (dst, str(dport))
    return (proto, *min(left, right), *max(left, right))


def parse_packet(raw: RawPacket) -> PacketRecord:
    d = raw.data
    fields = dict(time_ns=raw.time_ns, interface=raw.interface, linktype=raw.linktype,
                  source_id=raw.source_id, number=raw.number)
    issues = ["capture_truncation"] if len(d) < raw.original_length else []

    def fail(reason):
        return PacketRecord(**fields, issues=tuple(dict.fromkeys([*issues, reason])))

    if raw.linktype == 1:  # Ethernet, with up to two VLAN tags
        if len(d) < 14:
            return fail("malformed_ethernet")
        fields.update(dst_mac=d[:6].hex(":"), src_mac=d[6:12].hex(":"))
        ether, offset = struct.unpack_from("!H", d, 12)[0], 14
        for _ in range(2):
            if ether not in {0x8100, 0x88a8}:
                break
            if len(d) < offset + 4:
                return fail("malformed_vlan")
            ether = struct.unpack_from("!H", d, offset + 2)[0]
            offset += 4
    elif raw.linktype == 113:  # Linux cooked v1
        if len(d) < 16:
            return fail("malformed_sll")
        kind, hardware, length = struct.unpack_from("!HHH", d)
        if length > 8:
            return fail("malformed_sll")
        fields.update(capture_kind=kind,
                      src_mac=d[6:12].hex(":") if hardware == 1 and length == 6 else None)
        ether, offset = struct.unpack_from("!H", d, 14)[0], 16
    elif raw.linktype == 276:  # Linux cooked v2
        if len(d) < 20 or d[11] > 8:
            return fail("malformed_sll2")
        fields.update(capture_kind=d[10], src_mac=d[12:18].hex(":") if d[11] == 6 else None)
        ether, offset = struct.unpack_from("!H", d)[0], 20
    elif raw.linktype == 101:  # LINKTYPE_RAW
        ether, offset = (0x0800 if d and d[0] >> 4 == 4 else 0x86dd), 0
    else:
        return fail("unsupported_linktype")
    if ether == 0x0806:
        # Ordinary ARP is a registry observation, never an IPv4 feature.
        return PacketRecord(**fields, registry_only=True, issues=tuple(issues))
    if ether != 0x0800:
        return fail("unsupported_ipv6" if ether == 0x86dd else "unsupported_ethertype")
    ip = d[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return fail("malformed_ipv4")
    ihl, total = (ip[0] & 15) * 4, struct.unpack_from("!H", ip, 2)[0]
    fields.update(src=str(ipaddress.IPv4Address(ip[12:16])),
                  dst=str(ipaddress.IPv4Address(ip[16:20])), ip_length=total, ttl=ip[8])
    if ihl < 20 or total < ihl:
        return fail("malformed_ipv4")
    if len(ip) < total:
        return fail("truncated_ipv4")
    normalized = bytearray(ip[:total])
    normalized[8] = normalized[10] = normalized[11] = 0
    fields.update(view_fingerprint=hashlib.sha256(normalized).digest())
    fragment = struct.unpack_from("!H", ip, 6)[0]
    if fragment & 0x8000:
        return fail("malformed_ipv4")
    if fragment & 0x3fff:
        return fail("ipv4_fragment")
    proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip[9])
    if proto is None:
        return fail("unsupported_ipv4_protocol")
    fields.update(protocol=proto)
    payload = ip[ihl:total]
    if len(payload) < (20 if proto == "tcp" else 8):
        return fail("malformed_transport")
    if proto != "icmp":
        sport, dport = struct.unpack_from("!HH", payload)
        fields.update(sport=sport, dport=dport)
    if proto == "tcp":
        if not 20 <= (payload[12] >> 4) * 4 <= len(payload):
            return fail("malformed_tcp")
        fields.update(tcp_flags=payload[13])
    elif proto == "udp" and struct.unpack_from("!H", payload, 4)[0] != len(payload):
        return fail("malformed_udp")
    return PacketRecord(**fields, issues=tuple(issues))


def read_pcap(path, *, interface="offline"):
    """Classic PCAP, both byte orders and us/ns resolutions; no float clocks.

    Corrupt containers and PCAPNG fail explicitly. They must never look like a
    healthy empty capture. Records carry unsupported link types to the parser.
    """
    path = Path(path)
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Unsupported or corrupt capture container; expected classic PCAP")
        endian, multiplier = formats[header[:4]]
        _, major, minor, _, _, snaplen, network = struct.unpack(endian + "IHHIIII", header)
        if (major, minor) != (2, 4) or not 0 < snaplen <= 16 * 1024 * 1024 or network >> 16:
            raise ValueError("Unsupported PCAP version, snaplen or linktype flags")
        number = 0
        while h := f.read(16):
            if len(h) != 16:
                raise ValueError("Partial PCAP record header")
            sec, fraction, captured, original = struct.unpack(endian + "IIII", h)
            if fraction * multiplier >= SECOND or captured > snaplen or captured > original:
                raise ValueError("Invalid PCAP record lengths/timestamp")
            data = f.read(captured)
            if len(data) != captured:
                raise ValueError("Partial PCAP record data")
            number += 1
            yield RawPacket(sec * SECOND + fraction * multiplier, data, original,
                            network, interface, path.name, number)
