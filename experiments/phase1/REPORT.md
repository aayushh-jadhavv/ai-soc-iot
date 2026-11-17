# Phase 1 UNSW dataset and label audit

**Historical CSV-only audit.** On 17 November 2026, two original-format PCAPs,
BRO/Argus sources and the January provider report became available. Read the
[current raw-capture audit](raw-audit-001/REPORT.md) for the new inventory,
endpoint map, clock evidence, packet traces and remaining limitations. The
no-PCAP statements below describe the earlier input set and no longer describe
the workspace. Its CSV counts and duplicate findings remain relevant.

15 November 2026. **CSV audit complete; raw-packet acceptance gate blocked.**
The supplied data cannot establish the eight contiguous one-second endpoint
windows required by `device_window_v1`. The user confirmed no PCAPs are available.
No extraction, sequences, model scores, tuning or training were performed.

The user's Phase 1 request defines this work. The attached implementation plan
is a reference specification; its prompts for other phases are not instructions
to execute. Source plan SHA-256 is
`337c63bce40fccb319b9cba7f957cfaf1a099d95adc839e545a70bf4d1a4ae54`.
Repository base commit was `480a21bcff8050e4cc37dea267eaba857dd922aa`.

## Evidence and inventory

The authoritative run is [audit-002/audit.json](audit-002/audit.json), with full
per-file counts and hashes. [Flow annotation candidates](audit-002/flow_annotation_candidates.json)
retain the 1,336 sampled flows, tuples, timestamps, physical row numbers and every
candidate GT row. This is an explicitly limited flow diagnostic, not packet ground
truth. `audit-001` was superseded after fixing BOM parsing and is retained for
history. Inputs were hashed again after the scan to detect mutation.

The workspace was searched including Git-ignored data, excluding dependency and
Git internals. The supplied data directory contains ten files, no raw captures,
and no session/endpoint/clock/continuity manifest. Original capture/session IDs
are **unknown/null for every file**. None is replaced with a chunk number, UTC
date, prepared-row ID or invented session. Local acquisition URLs and publisher
checksum correspondence are also unverified.

| Supplied file under CSV-Files | Bytes | SHA-256 |
| --- | ---: | --- |
| NUSW-NB15_features.csv | 4,044 | c55f19cceebb6360dc50f44f8a5f246ccefbcf8a6c604ac1ad46e643869cafce |
| NUSW-NB15_GT.csv | 86,426,111 | 6d27542cb6457db599e0a78274ac141fec0296531f00ac5569551a276c5ab1a8 |
| The UNSW-NB15 description.pdf | 189,112 | 20784d87509db0185b5d816f01a4ea04e60be180798e2d38cabb500f6dd13999 |
| Training and Testing Sets/UNSW_NB15_testing-set.csv | 15,380,800 | 734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559 |
| Training and Testing Sets/UNSW_NB15_training-set.csv | 32,293,018 | bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa |
| UNSW-NB15_1.csv | 168,979,718 | 7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511 |
| UNSW-NB15_2.csv | 165,221,021 | 6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8 |
| UNSW-NB15_3.csv | 154,588,103 | ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640 |
| UNSW-NB15_4.csv | 97,588,754 | cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a |
| UNSW-NB15_LIST_EVENTS.csv | 4,639 | 5b40f8128e2c87e691157c76debde04c328b0eb66bab97f1e7e17625f84497f2 |

Preserve the supplied `NUSW` spelling. The official provider calls the GT table
`UNSW-NB15_GT.csv`; filename similarity is not authentication. The provider lists
raw PCAP/Bro/Argus sources, full CSVs and prepared subsets separately, and states
academic use and attribution terms. [Official UNSW source](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

## Row coverage and exclusions

All seven record tables were fully scanned; the four original flow chunks are
headerless 49-column files, GT has 12 columns, and prepared subsets have 45.
No malformed widths, negative timestamp intervals, invalid IPv4 endpoints,
invalid TCP/UDP ports or binary-label/family disagreements were found in those
tables. GT has no binary label field: its entries are attack annotations and the
audit's `1` is an explicit semantic classification, not an original field.

| Table | Rows | CSV benign | CSV attack | Repeat occurrences within file | Repeat occurrences matching a prior file |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full chunk 1 | 700,001 | 677,786 | 22,215 | 59,213 | 0 |
| Full chunk 2 | 700,001 | 647,252 | 52,749 | 63,248 | 1 |
| Full chunk 3 | 700,001 | 542,576 | 157,425 | 224,834 | 11 |
| Full chunk 4 | 440,044 | 351,150 | 88,894 | 133,325 | 1 |
| Prepared testing | 82,332 | 37,000 | 45,332 | 26,387 | 0 |
| Prepared training | 175,341 | 56,000 | 119,341 | 60,120 | 8,421 |
| Attack GT | 174,347 | 0 | 174,347 annotations | 6 | 0 |

Duplicate counts are repeated cell-equal row occurrences, not counts of unique
duplicate connections. Prepared comparisons omit only local `id` and retain
features and labels; full-flow comparisons include all 49 cells. Testing is
visited before training, so 8,421 training occurrences match a testing record.
This does not establish 8,421 distinct shared flows. No data has been deduplicated.

There are 2,540,047 full-flow rows: 2,218,764 CSV-benign and 321,283 CSV-attack.
The event summary totals 2,540,044, with 2,218,761 normal. All attack-family
totals agree. Exact last-row/next-first-row checks confirm duplicate benign
boundaries at chunks 1/2, 2/3 and 3/4; these account for the three extra rows.
Across the four chunks there are another substantial set of repeated row
occurrences: 480,620 within files and 13 matching prior files, including the
boundary copies. Equal coarse flow summaries do not prove duplicated packets.

| Canonical family | Full flow rows | Initial scope |
| --- | ---: | --- |
| Benign | 2,218,764 | Candidate normal, needs packet and normal-coverage verification |
| Reconnaissance | 13,987 | Candidate positive |
| DoS | 16,353 | Candidate positive |
| Exploits | 44,525 | Excluded |
| Generic | 215,481 | Excluded |
| Fuzzers | 24,246 | Excluded |
| Analysis | 2,677 | Excluded |
| Backdoor or Backdoors | 2,329 | Excluded |
| Shellcode | 1,511 | Excluded |
| Worms | 174 | Excluded |

There are 30,340 candidate in-scope attack flow rows and 290,943 out-of-scope
attack rows. Family normalization trims whitespace, lowercases, maps blank/Normal
to benign and Backdoors to backdoor; original text remains in the profile. These
are row-level descriptions only. **All supplied feature rows are ineligible as
temporal samples**, including the 257,673 prepared train/test rows; these subsets
are derived data and must not be added to the full-table population.

Verified original sessions: 0. Verified packet traces: 0. Constructible accepted
temporal sequences: 0. Packet/window label coverage fractions, benign device-hours,
packet exclusion counts and class support by original session are **undefined**,
not zero-percent coverage. There are no packet/window denominators to measure.
The GT has no normal annotation rows; absence of an attack match is not benign.

## Time units offsets and chronology

Full-flow `Stime/Ltime` and GT `Start time/Last time` are integral values consistent
with epoch seconds. They have no fractional timestamp rows. The following UTC
interpretation is a hypothesis, not verified capture synchronization:

| Table | Earliest start if epoch seconds | Latest end if epoch seconds |
| --- | --- | --- |
| Full chunk 1 | 2015-01-22 11:49:37Z | 2015-01-22 19:44:02Z |
| Full chunk 2 | 2015-01-22 19:43:15Z | 2015-02-18 03:45:29Z |
| Full chunk 3 | 2015-02-18 03:44:59Z | 2015-02-18 09:00:09Z |
| Full chunk 4 | 2015-02-18 08:59:44Z | 2015-02-18 12:21:09Z |
| Attack GT | 2015-01-22 11:50:14Z | 2015-02-18 12:21:09Z |

Chunk 2 includes starts on January 22, January 23 and February 18. Its date span
is not evidence of continuous recording. Chunk ranges overlap at each boundary.
Full-flow start times move backward 345,831 times in row order, so eight adjacent
CSV rows cannot mean eight chronological seconds. These are row-order effects,
not demonstrated capture-clock discontinuities.

2,008,887 full-flow rows and 119,367 GT rows have equal start/last timestamps.
They can still describe nonzero subsecond activity. Source rounding and inclusive
last-time semantics remain unverified. Do not blindly use `[start,last)` (which
empties those rows), add an unverified second, derive packet times from `dur`, or
shift records to maximize matches. Relative capture/annotation offsets, timezone
metadata and original timestamp resolution cannot be measured without captures
and provenance. No offset was selected. Milliseconds/microseconds interpretations
would not place these magnitudes in the observed 2015 epoch; that supports units
screening but does not verify synchronization.

## Tuples monitored endpoints and capture duplication

Full flows retain source/destination IPs, ports and protocol plus directional
aggregates. GT supplies corresponding tuple fields. Exact forward/reverse tuple
checks are implemented, with numeric/hex port handling. Observed tuple direction
is not an endpoint-role label. Prepared subsets omit IPs, ports, absolute times
and capture IDs, so they cannot recover it.

There are 49 distinct valid IPv4 strings across full flows and GT, including
multicast, loopback and apparent infrastructure addresses. The full list is in
the profiles. None has verified monitored membership, binding interval, sensor
side or NAT mapping. Do not mark every address as a monitored IoT device, infer
victim status from an address range, or fabricate broadcast recipients.

No two supplied files have the same SHA-256. **Capture-level duplication remains
unassessed**, because there are no PCAPs or sensor manifests. CSV duplicates are
not enough to distinguish repeated summaries, duplicate sensors, file overlap
or genuine retransmissions. Future packet checks must preserve retransmissions
and compare timestamps, bytes, interface/sensor provenance and overlap intervals.

## Representative trace review

The candidate audit inspects the first 32 rows per file/family/candidate UTC date,
not a random or representative population sample. It uses coarse inclusive
interval overlap, both tuple orientations and no inferred session. The 1,336
sample outcomes are 816 single matching-family candidates, 12 multiple
same-family candidates, 316 candidate family conflicts and 192 unmatched flows.
These are **not verified packet matches or packet coverage percentages**.

| Requested case | Supplied evidence and decision |
| --- | --- |
| Benign | Chunk 1 row 1: UDP `59.166.0.0:1390 -> 149.171.126.6:53`, timestamp 1421927414, CSV label 0. No GT candidate. It is a CSV-normal example, not a verified benign packet or normal-coverage interval. |
| Malicious | Chunk 1 row 23: TCP `175.45.176.0:13284 -> 149.171.126.16:80`, 1421927414–1421927416, Reconnaissance. GT row 2 has the same forward tuple, family and coarse interval. Retain as a candidate pending packet/clock/session evidence. |
| Reverse direction | No reverse-oriented GT candidate occurs in this bounded sample. No actual reverse packet is supplied. A separate synthetic TCP fixture reverses both IPs and ports and verifies matching the same annotation, with role `not_inferred`; it is not dataset validation. |
| Ambiguous supported protocol | Chunk 3 row 8555: TCP `175.45.176.0:20027 -> 149.171.126.19:80`, 1424231332–1424231333, CSV DoS. GT rows 62087 and 62088 match the same tuple/time but say DoS and Exploits. Quarantine; do not choose one family or convert ambiguity to benign. |
| Multiple same-family candidates | Chunk 2 row 387690: TCP `175.45.176.1:63180 -> 149.171.126.11:80`, 1424219865. GT rows 14971 and 14972 both say DoS. Preserve both source rows; do not count them as two independent attack observations. |

These references use physical row numbers, including the GT header. Source file
hashes above bind them to exact files. Actual benign/malicious/reverse/ambiguous
packet trace acceptance is still blocked; no packet IDs or packet bytes were
invented. Unsupported protocols also have candidate collisions, which must not
be resolved through generic TCP/UDP port assumptions.

## Final window target and split decision

The implemented policy labels **observed attack involvement in the final second**.
Both directions and either monitored endpoint can be involved; this does not
establish an attacker, compromise or victim culpability. Earlier seven seconds
provide context. Unknown traffic plus verified positive evidence stays positive
with a mixed-coverage flag, unless identity/coverage/conflicts invalidate it.
Benign and idle labels require independently verified normal coverage.
Conflicting and out-of-scope traffic is excluded. Whole-file labels and positives
through silent flow intervals are forbidden. Detailed precedence and caller
requirements are in [the Phase 1 contract](../../docs/phase1.md).

Propose whole independent-session groups at 60/20/20 train/validation/internal
test. If sufficient groups and both classes exist, reserve half of validation
for threshold selection, yielding 60/10/10/20. Keep original session chunks,
duplicate views, shared connections and both endpoint views together. At present
this is **not feasible to assign**: there are zero verified original session IDs.
CSV chunks and dates are not substitutes. Prepared training/testing assignments
are rejected for this temporal task.

If provenance later confirms too few independent sessions, obtain more groups or
disclose a chronological within-session fallback. Purge at least seven seconds
of shared history and all boundary-crossing connections on both sides, including
affected windows/sequences. Report post-purge support. Omit calibration if a
separate threshold subset is unsupported; disclose any development reuse. No
split, transform or threshold is fitted in Phase 1.

## Independent external adapter audit

CSE-CIC-IDS2018 and BoT-IoT are separately **not supplied/not validated**. The
[adapter audit](../../docs/phase1_external_adapters.md) specifies independent
clock, tuple, identity, continuity, duplicate and benign-coverage checks for each.
It records the different risks of host/day schedules and category-organized or
sampled Argus/CSV material. No external predictions, scores or tuning occurred.

The local `READMEforBoTIoT.png` is attribution material, SHA-256
`8c9c909bf8002f7b9c4639624ecd1468553afc1d41f0b88e36fcd4a1b7e3e779`, and is not a
dataset adapter input. The external review consulted primary documentation only:
[UNB CSE CIC IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) and
[UNSW BoT IoT](https://research.unsw.edu.au/projects/bot-iot-dataset).

## Missing files and next gate

The exact missing artifact list and required fields are in
[Raw capture gate and missing inputs](../../docs/phase1.md#raw-capture-gate-and-missing-inputs).
Supply one intact original UNSW capture/session and adjacent chunks, a source
capture index/continuity manifest, monitored endpoint/topology map, clock/interval
and normal-coverage provenance, and acquisition/license records. The existing GT,
events and full flow CSVs need not be supplied again. Matching Argus/Bro logs are
needed if annotation collisions cannot be resolved from the other evidence.
More independent sessions are needed for defensible partition feasibility.

Exact vendor PCAP basenames cannot be recovered from this package because its
capture index is missing. Inventing them would obscure the blocker. Prepared
records cannot reproduce packet order, within-second counts and flags, IP-byte
lengths, per-window population statistics, IAT distributions, idle observations,
capture loss or endpoint bindings. Even timestamped full flows lose those details.

Obtain original captures from the provider when available. Recording new lab
traffic later is possible, but creates a new dataset with fresh ground truth;
it does not reconstruct historical UNSW traffic. The user requested capture
guidance later, so no capture or dataset download was started.

## Verification and limits

All 9 Phase 1 tests passed. See [test output](test-results.txt) and
[verification hashes and boundary checks](verification.json). `git diff --check`
passed for tracked changes; the new Python modules were exercised by the tests
and full CSV audit.

The standard-library test suite exercises explicit timestamp conversion,
half-open boundaries, tuple/session/protocol mismatches, forward and reverse
matching, contradictory/duplicate annotations, normal/idle/unknown labels,
mixed positives, invalid coverage/identity, out-of-scope exclusions, BOM handling,
prepared ID-independent duplicate detection and the blocked extraction gate.
These synthetic fixtures validate policy/tool behavior, not real dataset labels.

The full Phase 0 regression suite could not run in the existing WSL environment:
the expected cache interpreter is absent and `.venv/bin/python` points to a
nonexistent `/home/aayus/.local/share/uv/python/...` path. No ML environment was
reinstalled or modified. The Phase 1 audit and tests use bundled Python 3.12.14
and do not import or change the model, preprocessing, contracts or export path.
