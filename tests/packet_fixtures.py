"""Independent byte construction for the hand-calculated Phase 2 fixture."""

import ipaddress
import struct

from ids.features.packets import RawPacket, SECOND

A, B, C = "192.0.2.1", "192.0.2.2", "192.0.2.3"


def frame(src=A, dst=B, protocol=6, length=40, flags=2, sport=1234, dport=80,
          fragment=0, ether=0x0800, ttl=64):
    header = bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, 7, fragment, ttl, protocol, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    if protocol == 6:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 123, 0, 0x50, flags, 1000, 0, 0)
    elif protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, length - 20, 0)
    else:
        transport = b"\x08\x00" + bytes(6)
    return header + ip + transport + bytes(max(0, length - 20 - len(transport)))


def raw(time_ns, data=None, **kwargs):
    data = frame(**kwargs) if data is None else data
    return RawPacket(time_ns, data, len(data), 1, "fixture")


def golden_packets():
    # Third outbound TCP is a real byte-identical retransmission of the first.
    return [raw(100_000_000), raw(200_000_000, src=B, dst=A, flags=0x12, sport=80, dport=1234),
            raw(300_000_000, protocol=17, length=60, dport=53),
            raw(500_000_000, src=B, dst=A, flags=4, sport=80, dport=1234),
            raw(700_000_000), raw(900_000_000, dst=C, protocol=1, length=28),
            raw(SECOND, protocol=17, length=28, dport=53)]


def pcap_bytes(packets, *, nano=False, endian="<", linktype=1):
    multiplier = 1 if nano else 1000
    result = struct.pack(endian + "IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4,
                         2, 4, 0, 0, 65535, linktype)
    for p in packets:
        seconds, remainder = divmod(p.time_ns, SECOND)
        result += struct.pack(endian + "IIII", seconds, remainder // multiplier,
                              len(p.data), p.original_length) + p.data
    return result
