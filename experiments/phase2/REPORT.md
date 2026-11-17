# Phase 2 implementation and verification

Phase 2 is implemented and verified on the available audited UNSW captures.
No training, model selection, calibration or external scoring was performed.
The resulting dataset is provisional: it uses chronological blocks within one
connected source group and has no retained validation DoS samples.

The authoritative build is [run-002](run-002/REPORT.md). Its 14 implementation
file hashes were fixed before extraction and checked again at completion.
The earlier development run is marked superseded. Both runs produced identical
raw and normalized arrays for all three partitions.

| Partition | Samples | Benign | Reconnaissance | DoS |
| --- | ---: | ---: | ---: | ---: |
| Training | 6,457 | 6,433 | 19 | 5 |
| Validation | 2,178 | 2,173 | 5 | 0 |
| Internal test | 2,513 | 2,501 | 11 | 1 |
| Total | 11,148 | 11,107 | 35 | 6 |

The extractor read 3,415,660 packet records and retained 1,708,290 observations
after removing only 1,707,370 audited forwarded copies. Genuine retransmissions
remain. It emitted 55,033 endpoint-seconds, including explicitly invalid partial
edges. Preprocessing was fitted once per unique training window, using 11,357
windows rather than repeatedly weighting overlapping samples.

## Verification evidence

- [116 passing repository tests](validation/test-results.txt) cover the shared
  extractor, live/offline adapters, lifecycle, dataset rules and existing
  contracts/model/logging/audit regressions.
- [Independent saved-artifact verification](run-002/verification.json) reopened
  17 artifacts, every window and every sample. Raw matrices, normalized tensors,
  metadata, final-second labels and the unique training fit set agree exactly.
- [Real UNSW hand check](validation/real_window_handcheck.json) compares eight
  original receive records against manual population calculations, both adapters
  and the full-capture dataset. The [PCAP](validation/hand_checked_unsw_window.pcap),
  [Wireshark ledger](validation/real-window-tshark.csv), and original frame numbers
  remain available. That endpoint sends 5 packets/289 IP bytes and receives
  3 packets/201 IP bytes in the checked second.
- [Synthetic hand-calculated fixture](../../tests/fixtures/device_window_v1.md)
  separately verifies exact second boundaries, zero rows and a byte-identical
  retransmission. [Wireshark decoding](validation/fixture-tshark.csv) agrees with
  its packet ledger.
- [Environment](validation/environment.txt), [validation summary](validation/verification.json),
  [source/code manifest](run-002/data_manifest.json), and
  [artifact checksums](run-002/artifact_checksums.json) preserve reproduction evidence.

## Exclusions and leakage

The [counts and leakage artifact](run-002/counts_and_leakage.json) contains the
partition counts, packet evidence, capture-quality reasons, source connection
families, device-hours and primary exclusions. Primary exclusions are 17,808
invalid-capture rows, 19,174 warmup rows, 1,940 unknown final labels, 1,667 rows
touched by crossing connections, 3,228 out-of-scope final labels and 68 unassigned
partial-edge rows. These counts sum with retained samples to all 55,033 rows.
Label certainty and capture validity remain independent metadata columns;
primary exclusion counts do not replace the separate label/coverage counts.

The 81 conservative crossing-connection units were purged before forming
samples. Every pair of partitions has zero shared window IDs and zero shared
connection IDs. **All partitions still share the same original connected source
group.** This is disclosed within-group evaluation, not an independent-session
result. There is no separate threshold/calibration partition.

## Data and gateway handoff

The shared APIs and their ownership boundary are documented in
[the Phase 2 implementation guide](../../docs/phase2.md). Both adapters call the
same parser and aggregation engine. Labels, sample IDs, original/local IDs,
final times, families, lifecycle and coverage live in Parquet metadata; `.npy`
files contain only the 16 numerical features. Unknown original provider IDs
remain null, while the accepted Phase 1 local group and endpoint IDs are preserved.

The existing local disk was sufficient, and original captures were read in place.
Temporary sort files were cleaned up. The provider's additional-capture link
redirected to Microsoft sign-in; no additional accepted captures were available
locally. Original session/device IDs and physical sensor drop counters also
remain unavailable. These limitations and absent validation DoS support prevent
a defensible dataset freeze for the next phase. No model performance or training
readiness is claimed.
