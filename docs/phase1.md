# Phase 1 dataset audit

Phase 1 implements a read-only source inventory, supplied-CSV consistency scan,
raw-packet diagnostics and a fail-closed label policy. On 17 November 2026 the
two supplied January PCAPs, BRO/Argus files and provider report were audited.
They cover about 27 minutes from one connected source group. The follow-up
[UNSW label verification](../experiments/phase1/raw-label-verification-002/REPORT.md)
establishes usable benign, reconnaissance and DoS final-window labels for a
conservative subset of the excerpt. Independent train, validation and test
partitions remain infeasible with the supplied group.

Read the [initial raw-capture report](../experiments/phase1/raw-audit-001/REPORT.md).
Its directory contains capture/source manifests, endpoint mapping, packet traces,
timing and capture-view diagnostics, provisional coverage counts and a conditional
partition proposal. The follow-up report contains the verified label counts.
The [earlier CSV report](../experiments/phase1/REPORT.md), `audit-002/audit.json`
and `flow_annotation_candidates.json` remain historical evidence. `audit-001`
is superseded after fixing BOM handling. Unknown original session IDs remain null.

## Reproduction

For the new raw audit, see the commands and input configuration in the
[raw-capture report](../experiments/phase1/raw-audit-001/REPORT.md#reproduction).
The following commands reproduce the earlier CSV audit:

The audit uses only Python's standard library. From the repo, with Python 3.12:

```sh
python -m ids.datasets.audit --data-root CSV-Files --output experiments/phase1/reproduction
python -m unittest discover -s tests -p test_dataset_audit.py -v
```

Each output directory must be new and outside the input directory. The audit
hashes every input before and after scanning and fails if it changes. It preserves
source filenames, physical CSV row numbers, hashes and source label text alongside
canonical family names. Headerless flows start at row 1; GT and prepared tables
have headers, so their first data row is 2. UTF-8 BOMs are removed before parsing;
non-BOM files use lossless Latin-1 decoding because the supplied feature
description includes legacy bytes. Hashes cover unchanged original bytes.
No original capture ID is synthesized.

Duplicate fingerprints hash decoded CSV cells before trimming or family
normalization. For prepared training/testing tables only, the local `id` column
is omitted. Counts refer to repeated row occurrences, not unique connections or
packet retransmissions. Files of each schema are visited in sorted path order;
an occurrence matching an earlier file is counted there, otherwise against its
first occurrence in the current file. No records are deleted.

The diagnostic sample takes the first 32 flows per canonical family, candidate
UTC date and file. It searches both full tuple orientations using inclusive
overlap of coarse start/last timestamps. This is more permissive than the final
packet policy and cannot establish a training label. No clock correction, inferred
session or packet reconstruction is applied. Sample proportions are not population
coverage estimates.

## Normalized packet label policy

`ids.datasets.label_policy` operates only on already verified normalized packet
evidence. It is a tested policy kernel, not a raw-capture adapter. A future adapter
must retain file/hash, packet index, source timestamp/resolution, corrected integer
nanoseconds, original session, annotation file/hash/row, binding and mapping
interval, candidate matches, exclusions and decision reason.

Timestamp conversion requires an explicit unit and additive offset. A verified
annotation needs a source session, exact protocol/tuple, established clock and
interval interpretation. All normalized intervals are half-open. Integer-second
GT start/last values must not be silently converted to zero-length intervals or
expanded by a second without verifying rounding and inclusive-end semantics.
Boundary uncertainty remains unknown. TCP/UDP ports are numeric, including
explicit hex tokens. ICMP/type/code and other non-port joins need separate adapter
rules; current policy examples cover TCP/UDP only.

For each monitored endpoint, use only actually observed packets in the final
aligned one-second window. Both tuple directions can match a verified connection.
Both endpoints can have attack involvement when both are monitored. The target
does not assert compromise, malicious intent, attacker identity or victim blame.
Never copy a file label to endpoints or fill silent connection intervals.

Decision precedence is:

1. Invalid capture coverage or endpoint identity excludes the window.
2. Contradictory verified annotations exclude it. Repeated same-family annotations
   retain provenance and require duplicate investigation; their count is not
   additional positive evidence.
3. Any verified out-of-scope attack excludes the window, including mixed-scope
   windows. This conservative Phase 1 refinement prevents unintended family
   inclusion. Initial scope is benign, reconnaissance and DoS.
4. At least one unambiguous in-scope attack packet makes it positive. Unknown
   additional traffic does not erase it; record mixed unknown coverage.
5. Benign requires complete, independently documented normal-label coverage and
   no unknown packets. An idle second also needs healthy continuous capture and
   valid binding. Silence alone is unknown.
6. Everything else is unknown and excluded from supervised targets.

Earlier seven seconds supply features, not the final label. Unknown earlier
labels alone do not invalidate good features. All eight seconds must still meet
capture continuity, feature validity and binding/session/revision contracts.
The policy kernel trusts its caller to supply filtered endpoint/final-window
evidence; it cannot certify provenance or capture quality itself.

## Grouped partition proposal

No row-level assignments are published. All original session IDs are unknown;
prepared split IDs are local row IDs. Date clusters must not automatically become
independent groups. The four full CSV chunks are not four sessions, and their
flow-record intervals overlap.

The two supplied PCAPs are positively linked by a receive/forward datagram pair
across their boundary. Keep both in `unsw-jan22-source-group`. The current
[partition proposal](../experiments/phase1/raw-audit-001/partition_proposal.json)
contains concrete chronological fallback boundaries and crossing-BRO-connection
lists; they are conditional diagnostics, not authorized training assignments.

Once provenance is available, build indivisible connected groups from original
sessions, chunk continuations, duplicate/overlapping sensors, both endpoint views
and shared connections. Preserve a source-ID-to-group map. Deduplicate capture
copies only with packet/sensor evidence, retaining genuine retransmissions.
Allocate whole groups before windows or sequences. Aim for 60% train, 20%
validation and 20% internal test, balancing class support at group level without
changing evaluation prevalence. Freeze assignments with source hashes and a seed;
report actual proportions, benign duration, positive seconds and family support.

If enough independent groups exist, divide validation into disjoint model/search
selection and threshold-only groups (proposed overall 60/10/10/20 allocation).
Every scored subset needs both classes and usable family support. Reserve the
threshold subset before model selection; optional score calibration must not
silently share selection data. Internal and external tests stay locked. There is
currently no evidence that four suitable independent subsets exist.

If only two original collection sessions are confirmed, a three-way independent
session split is impossible. Prefer more independent sessions. A disclosed
within-session fallback may use chronological development blocks and an untouched
terminal internal-test block, but it must:

- Exclude every sequence whose eight-second support crosses a boundary. At B,
  restart history and retain no right-side sequence ending before B + 8 seconds;
  equivalently purge at least seven seconds of shared context.
- Purge every connection spanning a boundary on both sides, including its
  packet-derived windows and sequences touching invalidated windows. A
  seven-second guard alone cannot remove long-connection leakage.
- Keep duplicates, both endpoints and capture views together or remove affected
  observations. Recheck source/group, connection and raw-window disjointness.
- Preserve observed prevalence and report lost support. If support collapses,
  declare the split infeasible. Grouped development folds or disclosed validation
  reuse are alternatives, with optional calibration omitted.

No preprocessing is fitted now. Later fitting uses unique training windows once,
never validation/test or repeated copies from overlapping sequences.

## Raw capture gate and remaining evidence

Existing files include `NUSW-NB15_GT.csv`, `UNSW-NB15_LIST_EVENTS.csv`,
`NUSW-NB15_features.csv`, all four full flow CSVs, prepared subsets, both supplied
PCAPs, BRO/Argus material and provider reports. Do not request them again.

| Artifact | Prepared now | Remaining limit |
| --- | --- | --- |
| Capture/source manifests | Full SHA-256 inventory, packet spans, timestamp resolution, chunk order, source collection labels and local grouping | Original unique session IDs, publisher checksum and exact acquisition time were not supplied; these remain null |
| Continuity and view evidence | Clean PCAP record ends, 9-microsecond boundary, one datagram crossing the boundary, paired receive/forward observations and timestamp reversal measurements | No sensor drop counters or interface identity in classic PCAP; missing packets cannot be ruled out from a clean file |
| Endpoint mapping | All 34 static report hosts enrolled by IP for this excerpt, roles separated from labels, other observed addresses excluded | Shared MAC addresses are not per-host identity; report router settings differ from some observed infrastructure |
| Annotation provenance | File hashes, source rows, BRO UIDs, Argus rows, packet anchors, exact BRO/PCAP alignment | GT/CSV coarse timing, inconsistent aggregation and reverse-label conflicts need conservative exclusions; silence is not verified normal |
| Partition proposal | Both chunks in one connected group; concrete conditional chronological boundaries and crossing-connection list | Independent train/validation/test and threshold subsets are infeasible from this one group |

The follow-up [label verification](../experiments/phase1/raw-label-verification-002/REPORT.md)
resolves the UNSW label sign-off on an observed subset. Original source identity
and unmeasured capture drops remain provenance limits. The proposed chronological
validation block contains no DoS windows with eight observed, valid seconds.

The later packet audit must report, by dataset/original session/class and endpoint
group: observed packets, verified benign/attack by family, unmatched, conflicts,
duplicate observations, unsupported protocol, fragments, truncation, clock or
mapping ambiguity, capture loss and out-of-scope traffic. Separate multi-reason
diagnostics from mutually exclusive primary exclusions. For windows report valid/
invalid, positive including mixed unknown, benign, unknown, conflicts, out-of-scope,
idle without normal evidence, history warm-up, split-boundary and crossing-connection
exclusions. Denominators must be explicit; undefined denominators stay null.

Before bulk extraction, trace actual benign, malicious, reverse and ambiguous
packets through bytes/timestamp, mapping, annotations and final decision. Inspect
subsecond boundaries and tuple reuse. Compare duplicate views while retaining
retransmissions. Resolve the gate from evidence; no percentage threshold substitutes
for label validity.

## Obtaining captures later

Matching historical UNSW captures must come from the provider; flow aggregates
cannot regenerate them. The official source page links PCAP, Bro, Argus and CSV
material. A bounded, adjacent excerpt is sufficient for source/adapter auditing
with its first/last partial windows excluded. All 80 captures are not required
for this Phase 1 audit. Broader training coverage or independent evaluation may
later require selected additional source groups; downloading all files would not
by itself create additional independent collection sessions. No additional
download or contact message was initiated.

New authorized lab captures are a separate dataset with new session IDs and fresh
ground truth. Saving traffic with Wireshark/dumpcap/tcpdump does not create
historical UNSW traffic or annotations. A follow-up can choose your interface and
monitored machines, verify clocks, record benign and controlled attack intervals,
preserve both directions, and create manifests and endpoint maps alongside PCAPs.

## External datasets

See [the independent adapter audit](phase1_external_adapters.md). Neither external
dataset has supplied packet data. Documentation review is complete; real adapter
validation is not. No predictions, performance metrics, thresholds or feature
choices were derived from external data.
