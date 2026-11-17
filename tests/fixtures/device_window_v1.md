# Hand-calculated packet fixture

`device_window_v1.pcap` is a seven-record Ethernet PCAP, authored for validation,
not a collected dataset or evidence of model performance. Healthy observation
is declared for [0,8) seconds. A, B and C are 192.0.2.1, .2 and .3.

| Event seconds | Direction | Header | IPv4 total length |
| --- | --- | --- | ---: |
| 0.1 | A to B | TCP 1234 to 80, SYN | 40 |
| 0.2 | B to A | TCP 80 to 1234, SYN ACK | 40 |
| 0.3 | A to B | UDP 1234 to 53 | 60 |
| 0.5 | B to A | TCP 80 to 1234, RST | 40 |
| 0.7 | A to B | Exact retransmission of record 1 | 40 |
| 0.9 | A to C | ICMP echo | 28 |
| 1.0 | A to B | UDP 1234 to 53, exact boundary | 28 |

For A in [0,1): four outbound packets, 168 IP bytes, two destination IPs,
two numeric destination ports, two TCP, one UDP, one ICMP, two SYN without ACK.
Its two inbound packets total 80 IP bytes, with one SYN ACK and one RST.
Outbound length mean is 168/4 = 42. Population variance is
(4 + 324 + 4 + 196)/4 = 132; standard deviation is sqrt(132).
The three outbound gaps are 200, 400, 200 ms. Their mean is 800/3 ms;
population standard deviation is sqrt(80000/9) ms.

B in [0,1) sends two 40-byte packets 300 ms apart and receives 140 bytes in
three packets. C only receives the 28-byte ICMP packet. At precisely 1.0,
the UDP belongs to [1,2), with no IAT carried over from the previous second.
All unspecified endpoint-seconds in [0,8) are zero rows. The JSON expectations
were calculated from this ledger, independently of production aggregation.
