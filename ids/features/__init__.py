"""Shared Phase 2 extractor boundary. Gateway and datasets use these same APIs."""

FEATURE_NAMES = (
    "out_packets", "in_packets", "out_ip_bytes", "in_ip_bytes",
    "out_unique_dst_ips", "out_unique_dst_ports", "out_tcp_packets",
    "out_udp_packets", "out_icmp_packets", "out_syn_no_ack", "in_syn_ack",
    "in_rst", "out_len_mean", "out_len_std", "out_iat_mean_ms", "out_iat_std_ms",
)
FEATURE_UNITS = ("packets", "packets", "bytes", "bytes", "addresses", "ports",
                 "packets", "packets", "packets", "packets", "packets", "packets",
                 "bytes", "bytes", "milliseconds", "milliseconds")

from ids.features.packets import PacketRecord, RawPacket, parse_packet, read_pcap
from ids.features.extractor import Binding, FeatureHistory, Registry, Window, WindowExtractor
from ids.features.adapters import LiveAdapter, OfflineAdapter

__all__ = ["FEATURE_NAMES", "FEATURE_UNITS", "PacketRecord", "RawPacket", "parse_packet",
           "read_pcap", "Binding", "Registry", "Window", "WindowExtractor", "FeatureHistory",
           "LiveAdapter", "OfflineAdapter"]
