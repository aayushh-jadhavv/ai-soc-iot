"""Reserved shared extractor boundary for Phase 2 offline/live adapters.

Both gateway and dataset tools must import the same future extractor here.
No packet parsing, history management or gateway policy is implemented in Phase 0.
"""

FEATURE_NAMES = (
    "out_packets", "in_packets", "out_ip_bytes", "in_ip_bytes",
    "out_unique_dst_ips", "out_unique_dst_ports", "out_tcp_packets",
    "out_udp_packets", "out_icmp_packets", "out_syn_no_ack", "in_syn_ack",
    "in_rst", "out_len_mean", "out_len_std", "out_iat_mean_ms", "out_iat_std_ms",
)
FEATURE_UNITS = ("packets", "packets", "bytes", "bytes", "addresses", "ports",
                 "packets", "packets", "packets", "packets", "packets", "packets",
                 "bytes", "bytes", "milliseconds", "milliseconds")
