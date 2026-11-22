"""Common packet-to-record parser used by live capture and PCAP replay."""
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


def parse_packet(pkt, registry):
    ts_ns = int(pkt.time * 1_000_000_000) if hasattr(pkt, 'time') else time.time_ns()
    ts_ms = ts_ns // 1_000_000
    if pkt.haslayer(ARP):
        return []
    if pkt.haslayer(IPv6) and not pkt.haslayer(IP):
        # No device-level attribution guaranteed in the IPv4-only v1 contract.
        return [{'event_time_ms': ts_ms, 'valid': False,
                 'reason': 'unsupported_ipv6_v1', 'scope': 'global'}]
    ip = pkt.getlayer(IP)
    if ip is None:
        return []
    src, dst = str(ip.src), str(ip.dst)
    src_local, dst_local = registry.is_monitored_ip(src), registry.is_monitored_ip(dst)
    if not (src_local or dst_local):
        return []
    affected = [(src, 'OUT')] if src_local else []
    if dst_local:
        affected.append((dst, 'IN'))
    total_len = int(ip.len) if ip.len is not None else len(bytes(ip))
    invalid = None
    if int(ip.frag) or (int(ip.flags) & 1):
        invalid = 'fragmented_ipv4'
    elif total_len < 20 or int(ip.ihl or 5) * 4 > total_len or len(bytes(ip)) < total_len:
        invalid = 'truncated_or_malformed_ipv4'
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(int(ip.proto), 'OTHER')
    if protocol == 'OTHER':
        invalid = invalid or 'unsupported_ipv4_protocol'
    flags = int(pkt[TCP].flags) if protocol == 'TCP' and pkt.haslayer(TCP) else 0
    if protocol == 'TCP' and not pkt.haslayer(TCP):
        invalid = invalid or 'missing_tcp_header'
    if protocol == 'UDP' and not pkt.haslayer(UDP):
        invalid = invalid or 'missing_udp_header'
    port = int(pkt[TCP].dport) if protocol == 'TCP' and pkt.haslayer(TCP) else (
        int(pkt[UDP].dport) if protocol == 'UDP' and pkt.haslayer(UDP) else None)
    records = []
    for ip_addr, direction in affected:
        dev = registry.get_device(ip_addr)
        record = {'event_time_ms': ts_ms, 'event_time_ns': ts_ns, 'device_ip': ip_addr,
                  'device_id': dev['device_id'],
                  'binding_revision': dev['binding_revision'],
                  'identity_conflict': dev['conflict'],
                  'direction': direction, 'src_ip': src, 'dst_ip': dst,
                  'protocol': protocol, 'dst_port': port, 'ip_bytes': total_len,
                  'syn_no_ack': bool(flags & 2) and not bool(flags & 16),
                  'syn_ack': bool(flags & 2) and bool(flags & 16),
                  'rst_set': bool(flags & 4), 'valid': invalid is None,
                  'reason': invalid}
        if dev['device_id'] is None:
            record.update(valid=False, reason='unknown_device_binding')
        elif dev['conflict']:
            record.update(valid=False, reason='ambiguous_device_binding')
        records.append(record)
    return records
