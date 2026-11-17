# UNSW final window label verification

**The Phase 1 UNSW label check passed for the two supplied January 22 captures.**
All three proposed classes have verified packet-to-annotation joins and labeled
final windows with eight observed, valid seconds. The earlier packet audit and
partition proposal remain the source for capture provenance.
[Initial capture audit](../raw-audit-001/REPORT.md)

| Class | Verified connections | Labeled final windows | With eight observed, valid seconds |
| --- | ---: | ---: | ---: |
| Benign | 35,038 | 25,488 | 11,414 |
| Reconnaissance | 162 | 221 | 44 |
| DoS | 9 | 15 | 6 |

Of 38,080 observed endpoint-seconds, 25,724 received a verified label. The other
12,356 were excluded for invalid coverage (912), unknown final labels (3,970),
confirmed or possible out-of-scope attack involvement (7,472), or contradictory
annotations (2). Another 16,919 full endpoint-seconds had no observations and
remain unlabeled. The stricter coverage pass rejected 49 otherwise matching
benign connections with BRO-reported content gaps.

The two files form one capture group. DoS support with eight observed seconds
spans four distinct final seconds, with zero in the proposed chronological
validation block even before boundary purges. The label check closes the
Phase 1 UNSW label item. Independent evaluation and a viable three-way
partition remain open. [Partition proposal](../raw-audit-001/partition_proposal.json)

## What qualifies as a verified join

1. Match packets by protocol and the complete bidirectional endpoint tuple.
   Rounded source seconds narrow which flow rows a packet could belong to.
   If any packet could belong to more than one full-CSV flow, exclude the
   competing flows. Exclude flows whose candidate interval reaches past the
   observed capture edges.
2. Reconstruct the exact first and last packet times, forward and reverse
   packet counts, and both IPv4 byte totals from the PCAP. Require the rounded
   endpoints and directional counts and bytes to agree with the labeled
   full-CSV row, and the duration to agree within one microsecond. Require a
   unique matching Argus row and a unique BRO start at the exact first packet
   timestamp. Exclude joins with BRO-reported missing connection bytes.
3. Require one ground-truth row with the same oriented tuple, coarse bounds
   and family for an attack. For benign, require explicit full-CSV label
   zero and no competing attack annotation. Conflicting annotations, reused
   tuples that cannot be disambiguated and unmatched rows are excluded from
   verified joins. The labeled CSV and ground truth are both provider
   annotations. BRO and Argus corroborate the connection reconstruction.

The nearest-second rule is supported by observed start-time alignment in the
initial audit and applied here only when the raw counts, bytes, duration and
connection anchors also agree. Packet labels use the actual packet timestamps
and the reconstructed exact connection span. For example, an attack recorded
with a rounded time of 1421927955 can contribute a packet to the actual
endpoint window `[1421927954, 1421927955)`.

Compare provider flow signatures using both original capture views. For window
labels keep the receive timestamp of each one-to-one receive/forward pair,
using matching IPv4 bytes with only TTL and header checksum masked and a
one-hop TTL decrement. The scan reproduced 1,707,370 pairs, including one
straddling the file boundary. Later retransmissions remain observations.

## Final window decisions

Assign the binary label from the final one-second interval, independently of the
earlier seven seconds. Both directions of a verified attack connection count as
observed involvement at either monitored endpoint. A benign window requires
verified normal evidence for every retained relevant observation. Exclude quiet
seconds with no independent evidence of healthy capture, contradictory joins,
and windows with possible out-of-scope attacks or observed invalid coverage.
Mark mixed unknown traffic when a verified in-scope attack still determines the
positive label.

For the strongest demonstrated subset, require eight consecutive observed
seconds with valid endpoint and packet coverage, including the labeled final
second. Observed coverage excludes partial edges, capture timestamp gaps, BRO
content gaps and unsupported or malformed observations at the endpoint. Sensor
drop counters are unavailable. The counts establish a bounded label check
under these coverage rules. They cannot estimate how much traffic the capture
missed before it was written.

## Independent packet checks

Wireshark reproduced the raw first and last timestamps and the directional
packet and byte totals for one accepted window from each class. Those totals
were checked against the original full CSV, Argus and BRO rows. The two
attack examples also match their original ground-truth rows.

| Class | Final second (Unix UTC) | PCAP 1 frames | Full CSV row | Argus row | BRO UID | GT row |
| --- | ---: | --- | ---: | ---: | --- | ---: |
| Benign | 1421927421 | 942–945 | 75 | 156 | `CuY9xN2yE7OOX362qj` | — |
| Reconnaissance | 1421927589 | 362352–362353 | 4867 | 4806 | `CHTSNV3iALkSNEID97` | 192 |
| DoS | 1421927954 | 1063007–1063008 | 13504 | 13243 | `CeGqwv33WAjqx0nXWg` | 996 |

## Reproduction

From the repository using Python 3.12 or later, choose a fresh output directory.

```powershell
python -m ids.datasets.verify_unsw_labels --config experiments/phase1/raw-audit-001/config.json --output experiments/phase1/label-verification-reproduction
python -m unittest tests.test_dataset_audit tests.test_packet_audit tests.test_verify_unsw_labels -v
```

The verification checks source and capture hashes against the initial manifest.
All 20 targeted audit and label tests passed.
Artifacts include the machine-readable decision and counts, accepted final-window
labels with source row references, and compressed JSON Lines with verified
connection joins and raw record witnesses.

- [Verification result](verification.json)
- [Verified final windows](verified_final_windows.csv)
- [Verified connection joins](verified_joins.jsonl.gz)
- [Independent packet and source-row cross-check](evidence_crosscheck.json)
