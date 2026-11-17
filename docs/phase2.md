# Phase 2 shared features and temporal dataset

Phase 2 implements `device_window_v1`, PCAP and live callback adapters, temporal
samples, training-only preprocessing, and exclusion/leakage reports. It does
not train, tune, score external data, install capture drivers, or implement the
gateway policy worker. The user's Phase 2 request controls scope; prompts for
other phases in the attached plan are reference text.

## Reproduce

Use Python 3.12. The data path has no dependency on PyTorch or ExecuTorch.
The isolated `.venv-phase2` used for verification does not replace the existing
Linux Phase 0 environment or change `uv.lock`.

```powershell
python -m venv .venv-phase2
.\.venv-phase2\Scripts\python.exe -m pip install -r requirements-phase2.txt
.\.venv-phase2\Scripts\python.exe -m pytest tests/test_features.py tests/test_temporal.py tests/test_contracts.py tests/test_dataset_audit.py tests/test_packet_audit.py tests/test_verify_unsw_labels.py -q
.\.venv-phase2\Scripts\python.exe -m ids.datasets.build_temporal --output experiments/phase2/reproduction
.\.venv-phase2\Scripts\python.exe -m ids.datasets.check_temporal experiments/phase2/reproduction
.\.venv-phase2\Scripts\python.exe -m scripts.check_phase2_evidence experiments/phase2/reproduction
```

The output directory must be new. `--config` and `--verification` default to the
accepted Phase 1 January capture evidence. The source paths are read from that
hash-bound config. An altered source, endpoint map, or absent label signoff must
be audited before it becomes a new accepted input. `--scratch` defaults to
`tmp/phase2/sort`; reserve at least twice the capture bytes, with a 4 GiB minimum.
Original captures remain in place. Temporary external-sort runs are removed on
normal completion and exceptions.

`requirements-phase2.txt` pins the data/test environment. To run the unchanged
model regression tests as well, install `torch==2.9.0` from the CPU index specified
in `pyproject.toml`, then run `python -m pytest -q`. This runs tests, not training.

## One shared owner surface

Both the gateway owner and the CNN dataset owner import `ids.features`. Make
parser, window-statistic and lifecycle changes there, with the common fixture
tests. Do not copy the Phase 1 audit parser into the gateway. That older parser
remains unchanged as the implementation that produced the historical audit.

| Module | Responsibility |
| --- | --- |
| `ids/features/packets.py` | Integer-nanosecond `RawPacket` and `PacketRecord`; one byte parser |
| `ids/features/extractor.py` | Static interval registry, window aggregation, coverage, lifecycle and eight-row history |
| `ids/features/adapters.py` | Bounded external PCAP sorting and live libpcap callback/timer adapter |
| `ids/features/views.py` | Explicit selection for the audited UNSW duplicate observation point |
| `ids/datasets/temporal.py` | Frozen partitions, connection purges, samples and storage |
| `ids/datasets/unsw_temporal.py` | Phase 1 verified packet-label evidence and original provenance |
| `ids/preprocessing.py` | Shared normalization, unique training-window fit and inference transform |

This is the gateway handoff contract. No teammate was contacted or assigned
ownership on their behalf. No gateway service or firewall configuration changed.

## Packet and time semantics

The parser accepts complete, nonfragmented IPv4 TCP, UDP and ICMP on Ethernet
(including up to two VLAN tags), Linux cooked v1/v2 and raw IPv4. Unsupported
link types, IPv6, unsupported IPv4 protocols, malformed headers, fragmentation
and truncation become coverage flags. A corrupt container or PCAPNG fails
explicitly; it cannot silently become an empty capture. Classic PCAP supports
both byte orders and microsecond/nanosecond timestamps without floating-point
epoch conversion. Checksum validation and reassembly are outside v1.

Every packet updates its monitored source as outgoing and its monitored
destination as incoming. Remote/router MACs never establish device identity.
Broadcast and multicast have no fabricated recipient fan-out. Ordinary ARP
is a registry observation with no model count or invalidation. DHCP remains an
ordinary supported UDP observation; discovery is the gateway registry's job.

All windows are integer-second `[start,end)` intervals. IP bytes are the IPv4
total length. Lengths and outgoing within-window IATs use online population
moments. There is no IAT across a second boundary. Zero outgoing packets have
zero outgoing statistics; one outgoing packet has zero deviations and IAT;
one gap has zero IAT deviation. Physical retransmissions always count.

PCAP records are externally sorted across all chunks of the accepted original
group. Sorting is stable and bounded to 50,000 records per in-memory run. No
general packet deduplicator exists. The UNSW-only view selector removes an
audited one-to-one SLL forwarded copy only with equal IPv4 bytes after masking
TTL/checksum, a one-hop TTL decrement and at most 100 ms delay. It preserves
every receive observation, repeated retransmissions and unpaired outgoing
observations. Both chunks and endpoint views retain the same source group.

## Live adapter contract

Create a `WindowExtractor` with a `Registry` of time-bounded `Binding` records.
Construct `LiveAdapter` once with its selected observation interface, event-time
anchor and monotonic anchor. Pass a copied libpcap frame through
`from_libpcap(seconds, fraction, captured_bytes, original_length, linktype=...,
monotonic_ns=..., precision="us")`. `receive(RawPacket, monotonic_ns=...)` is the
equivalent callback boundary. These APIs are tested without needing capture
privileges or an installed Windows capture driver.

Call `tick(monotonic_ns)` during silence as well as traffic. It finalizes whole
seconds after the 100 ms ordering allowance, sorting within each second before
aggregation. The fixed event-to-monotonic mapping detects excessive timestamp
skew. Time values must be exact integers. A backward monotonic clock is an
explicit error. An actual backward event-clock step requires a new extractor
and capture session; do not sort across that discontinuity as one healthy session.

The queue holds at most 65,536 records. Overflow records are dropped with their
affected interval flagged for every active device when attribution is unknown.
Forward libpcap/OS loss-counter deltas through `report_drop`; report interrupted
input intervals with `extractor.quality(start_ns, end_ns, "input_gap")`. Capture
health is an adapter responsibility; absence of packets alone does not prove a
gap. A healthy empty interval emits valid zero rows. Repeated drop flags coalesce
internally so overload cannot create an unbounded second queue of flags.

Use one serialized capture worker for callbacks, timers, quality events and
resets. `on_quality` receives the exact affected interval and whether it was
reported after finalization. Already emitted windows remain immutable; late
arrivals are rejected, current coverage is invalidated, and the lifecycle
changes. The gateway should clear affected `FeatureHistory` objects immediately
on these quality events. It must never reuse an older score as a healthy result.

`FeatureHistory.append(Window)` returns eight rows only when identity, binding,
session, boot, enforcement, observation mode, lifecycle, sequence numbers and
timestamps are continuous and all rows valid. Invalid coverage clears history.
`LiveAdapter.reset` drops queued backlog with an explicit coverage event, then
resets boot/session/enforcement context. Call it for worker restart or enforcement
changes; use an explicit reset reason for model/schema activation. The numerical
feature contract is unchanged.

Static registries above 128 distinct devices fail before capture. Simultaneous
address claims invalidate affected identities. Binding revision changes reset
history even during silence. Unique destination IP/port sets cap at 4,096;
overflow invalidates the row and marks retained counts as lower bounds. It never
claims clipped uniqueness is exact. After 60 seconds without endpoint traffic,
stop emitting complete rows whose end exceeds the deadline. Reactivation creates
a new lifecycle and needs eight fresh rows.

## Partitions, labels and preprocessing

The split manifest is written before extraction and sample formation. Preferred
independent splits reject source groups assigned to multiple roles. The supplied
two-file excerpt has only one connected group, so the executable records the
pre-existing Phase 1 chronological ranges as `within_group_chronological`.
It never renames chunks or individual endpoints into independent groups.

No sequence crosses a partition. Seven final seconds of warmup precede the
first possible eight-row sample in each block. Entire windows touched by any
boundary-crossing connection are purged on both sides, and histories reset.
Crossings include BRO, GT and full-CSV candidate spans plus observed packets.
Bidirectional tuple reuse is grouped conservatively as one leakage unit;
this can remove extra windows rather than split a real connection. Reports
explicitly distinguish zero shared windows/connections from the remaining
shared source group in chronological evaluation.

Only the final second supplies a sample label. A verified attack packet at
either endpoint creates attack involvement, including replies and potential
victims. Verified positives can retain mixed unknown traffic. Contradictions
and possible out-of-scope attacks are excluded. Benign requires every relevant
observation to have verified normal evidence. No whole-file attack labels,
silent positive flow spans, or automatic benign silence are introduced.

Unknown annotation labels do not make capture invalid. Earlier unknown labels
can be valid feature context. Capture quality and label quality are separate
metadata fields and separate report counts. The supplied UNSW captures lack
physical drop counters: silence is marked `capture_health_unverified`, while
known audit gaps, BRO missing bytes, parser issues and partial edges are invalid.
V1-supported ICMP contributes features but may have unknown labels; it is not
misclassified as an unsupported protocol solely because the label join lacks it.

`fit_unique_training_windows` fits log1p feature means and population deviations
only on the unique valid windows used by retained training samples. Repeated
overlapping sample occurrences do not increase a window's weight. Invalid and
non-training fit inputs fail. `preprocess.json` saves feature order/units,
transform version, population convention, epsilon and the fit-ID hash;
`fit_window_ids.json` provides the full audit set. Dataset and runtime inference
share the same numerical transform, with float32 `[N,16,8]` output.

## Artifacts and verification

- `windows.parquet`: raw 16-value rows plus identities, lifecycle, coverage,
  independent label metadata, source references and primary exclusions.
- Per-partition `raw.npy`: numeric-only `[N,8,16]` measurements.
- Per-partition `tensor.npy`: numeric-only normalized float32 `[N,16,8]`.
- Per-partition `samples.parquet`: sample ID, local and original group/device
  IDs, exclusive final time, final-second start, label, family, coverage, row IDs
  and array row index. Original provider IDs remain null when unavailable;
  existing Phase 1 local endpoint/group IDs are preserved without substitution.
- `data_manifest.json`, `split_manifest.json`, `preprocess.json`, quality events,
  counts/leakage report, checksums and `REPORT.md`.

Parquet row groups are bounded to 4,096 windows. The executable builds this
bounded audit excerpt's row/sample metadata in memory; larger collections should
be processed group by group with the same fixed split manifest. Packet parsing
and ordering never load the full capture bytes in memory.

The hand-calculated ledger is in `tests/fixtures/device_window_v1.md`, with its
PCAP and independent expected JSON. Tests check exact boundaries, retransmissions,
reverse traffic, population moments, ARP, malformed/unsupported inputs, caps,
loss, late events, resets, identity changes, inactivity and offline/live parity.
Dataset tests cover final-only labels, unknown context, group guards, purges,
train-only unique fitting and metadata/tensor separation. `check_temporal` also
reopens real saved artifacts, recalculates preprocessing and checks cross-partition
window/connection overlap independently of the builder.

`experiments/phase2/validation` also contains a hand-checked real UNSW window.
Wireshark independently lists 16 original records in that second, of which
eight are the receive observations after the audited view selection. The
monitored endpoint sends five packets totaling 289 IP bytes and receives three
totaling 201. Outgoing lengths are 56, 52, 73, 56, 52 bytes; outgoing IATs are
0.753, 99.262, 1.316, 0.707 ms. The check compares the independent population
calculations against both adapters and the saved full-capture window. The
complete eight-record PCAP and source frame numbers remain available for review.
