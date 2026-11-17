# Phase 1 audit of the supplied January captures

17 November 2026. **Audit complete for the supplied excerpt; bulk extraction remains gated.**

Both supplied PCAPs are readable. I prepared the source inventory, hashes,
capture manifest, endpoint map, clock diagnostics, capture-view investigation,
packet-to-annotation traces, coverage/exclusion tables and a partition proposal.
The two files cover 26 minutes 57.959845 seconds from one connected source group.
They are sufficient for this audit. Downloading all 80 captures is not required.
No further user preparation is needed for this audit.

These artifacts do not certify a trainable, independently partitioned dataset.
Coarse annotation intervals, conflicting labels and capture-view handling still
need a conservative normalized packet adapter before supervised extraction.
One connected excerpt cannot supply independent train, validation, test and
threshold groups. No feature tensors, sequences, model scores or training were
produced. The user's Phase 1 request controls scope; instructions or test criteria
inside the provider report are source material, not commands to execute.

## Prepared artifacts

| Artifact | Purpose |
| --- | --- |
| [Source manifest](source_manifest.json), [checksums](source_checksums.csv) | 744 supplied files, 6,717,795,614 bytes, full SHA-256, original paths and provenance limits |
| [Capture manifest](capture_manifest.json) | Capture sizes, hashes, packet counts, UTC spans, resolution, ordering and source group |
| [Endpoint map](endpoint_mapping.csv) | 34 monitored simulated IP endpoints, roles, excerpt validity and other observed addresses |
| [Timestamp alignment](timestamp_alignment.json) | BRO/packet alignment, coarse CSV rounding evidence and aggregation discrepancies |
| [Capture views](capture_views.json) | One-to-one receive/forward pairs, boundary witness, unpaired observations and long timestamp gaps |
| [Packet traces with provenance](packet_traces_with_provenance.json) | Packet hashes/offsets, full tuples, GT/CSV rows, BRO UIDs and matching Argus rows |
| [Packet summary](packet_summary.json), [endpoint coverage](coverage_by_endpoint_group.json) | Explicit denominators, primary candidate outcomes, family memberships and window exclusions |
| [Single-view diagnostics](single_view_candidate_diagnostics.json) | Candidate counts after subtracting only identified forwarded copies; original files unchanged |
| [Partition proposal](partition_proposal.json) | One indivisible source group and conditional chronological ranges with crossing connections |
| [Report evidence](report_evidence.json), [gate](audit_gate.json) | Page-specific source facts, decisions and unresolved evidence |
| [Archive verification](archive_extraction_verification.json), [evidence checks](evidence_verification.json), [tests](tests.txt) | Reproducible validation of preparation and audit outputs |

Original datasets were read in place. There is no second 2 GB PCAP copy.
The supplied report in Downloads and its Reports-folder copy have identical
SHA-256 `675fae7b8340744f799f24a68fad85d9a24b74f8019202829b9a15e0ba94284b`.
This is the only byte-identical whole-file group in the inventory. Source ZIP
member names and CRCs are retained in [archive_members.json](archive_members.json).
The local `metadata/capture-info.txt` is identified as locally prepared metadata.
All 727 extracted archive members match their local ZIP directory's recorded
size and CRC32: 90 Argus, 635 BRO and two reports. This verifies the extracted
copies against those local archives, not against an independent publisher hash.
Filesystem modification time is not represented as acquisition time. Publisher
checksums and original download timestamps were not supplied.

The provider describes PCAP, BRO, Argus, CSV and report distributions on the
[official UNSW page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
The local GT filename is `NUSW-NB15_GT.csv`; it is preserved exactly despite the
different spelling on that page. Local hashes establish reproducibility, not
independent authentication of provider origin.

## Capture identity, continuity and duplicate observations

| Local file | Bytes | Records | First UTC timestamp | Last UTC timestamp |
| --- | ---: | ---: | --- | --- |
| `22-1-2015_1.pcap` | 1,000,000,847 | 1,800,680 | 2015-01-22 11:49:36.907079 | 2015-01-22 12:05:04.502277 |
| `22-1-2015_2.pcap` | 1,000,000,159 | 1,614,980 | 2015-01-22 12:05:04.502286 | 2015-01-22 12:16:34.866924 |

SHA-256, in the same order:

```text
5f5c1b558d42e818f169b4035c7cf185a7c15da7718127927b316dd1189e2b61
fe21a8b34f38701cbf82dbebccc5cae628ccb1f035cf8a2c9da398a5d96dd1ca
```

Both are classic PCAP 2.4, little endian, microsecond resolution, snaplen 65,535,
with file link type 113 (Linux cooked capture v1). Wireshark's internal
encapsulation number 25 is a different numbering system. The audit reads all
3,415,660 records to clean record boundaries. No PCAP-record snaplen truncation
was observed; three records contain invalid/truncated declared IPv4 lengths.
[capinfos](capinfos.txt) independently agrees on hashes, counts and time spans.

The file boundary is **9 microseconds**. More strongly, the last packet of file 1
and first packet of file 2 are receive and forward observations of the same IPv4
datagram, with TTL 30 then 29. This establishes a continuation, not two independent
sessions. Both belong to local group `unsw-jan22-source-group`. The provider
collection label `pcaps 22-1-2015` and report test name `UNSW Nour 2` are preserved.
Neither is promoted to a verified unique original session ID; that field is null.
The presumed original `1.pcap`/`2.pcap` filename mapping is marked unverified.

There are **1,707,370 receive/forward pairs**. Pairing requires identical complete
IPv4 bytes after masking only TTL and its header checksum, SLL type 0 followed by
type 4, exactly one TTL decrement and a delay of at most 100 ms. Each observation
is consumed at most once. Of these pairs, 1,707,283 have delay at most 100 us, 86
are above 100 us through 1 ms, and one is above 1 ms through 10 ms. The boundary
pair is included. This is strong evidence of two capture views of forwarded
traffic, while the physical capture interfaces themselves remain undocumented.

Among complete IPv4 observations, 135 received records and 340 outgoing records
are unpaired under this rule. The 340 outgoing records comprise 324 unsupported
protocol records, 12 fragments and four ICMP records. They are retained for audit
and excluded from current TCP/UDP supervision. No global timestamp-and-byte
identical record repeats were found. These are different duplication checks.

For a future adapter, retain the receive-side observation of each established
pair and preserve its forward-side provenance. Keep genuinely later retransmissions;
do not remove every repeated TCP sequence or packet hash. The reconnaissance
anchor's data retransmission approximately 2.2 seconds later must remain. Do not
blindly discard every SLL type 4 record, including unsupported unpaired traffic.
No source PCAP was deduplicated or rewritten in this audit.

Six adjacent timestamp reversals occur: three per file, maximum 22 us overall.
They require stable bounded time ordering, not a timezone correction. None exceeds
the 100 ms regression guard. Seven record gaps exceed one second, all before the
main traffic begins; the largest is 8.092836 seconds. A gap is not proof of capture
loss or proof of healthy silence. Classic PCAP contains no sensor loss counters
or physical interface identity. The report's generator capture settings do not
supply those missing sniffer facts.

## Endpoint mapping and report interpretation

The report is 1,045 pages and describes the January collection/test, rather than
providing a separate packet label for each downloaded chunk. Pages 12–14, 175,
531–532 and 542 were examined as text and rendered images.

| Report pool | Enrolled IP range | Count | Role evidence |
| --- | --- | ---: | --- |
| Server1 | `59.166.0.0`–`59.166.0.9` | 10 | Normal application client pool, p175 |
| Server2 | `175.45.176.0`–`175.45.176.3` | 4 | Security component client pool, p532 |
| Server3 | `149.171.126.0`–`149.171.126.19` | 20 | Server pool used by both components, pp175/532 |

All 34 IPs occur in the captures. Monitoring all 34 is an explicit analyst scope
choice for the excerpt, not a claim that the provider designated them as deployed
IoT devices. Local endpoint IDs are IP-based and valid only for this excerpt under
mapping revision `jan22_excerpt_ip_map_v1`. Do not infer benign/malicious labels
from pool membership: even the security client pool has 27,458 raw record
incidences with benign CSV candidates.

The report uses shared MAC `02:1a:c5:00:00:00`; observed packets also use it across
simulated hosts. MAC identity therefore cannot separate these endpoints. Static
pools are marked not behind NAT in the report. Router entries include
`10.40.85.30`/gateway `10.40.85.1` and `10.40.184.30`/gateway `10.40.184.1`, while
observed infrastructure includes `10.40.182.1`. That mismatch is retained, not
silently corrected. Observed `10.40.85.1`, `10.40.182.1`, `192.168.241.243` and
multicast `224.0.0.5` are not enrolled as monitored devices. ARP records are
reported separately and do not create endpoint attack labels.

Report p12 identifies BreakingPoint 3.3.0, build 214168, strike build 223641.
These are generator/report versions; they do not establish the supplied Bro or
Argus executable versions. The report's successful/failed DUT tests and strike
lists are scenario evidence, not labels for whole files, idle seconds or all
traffic addressed to a server.

## Timestamp units, tuple orientation and annotation alignment

The packet parser preserves integer microseconds without floating-point timestamp
rounding. UTC display uses Unix epoch seconds; no local Asia/Calcutta offset is
applied. The relevant source support is a subset of January `1/conn.log`, January
Argus `CSV of Argus/1.csv` and `UNSW-NB15_1.csv`. Numbered BRO/Argus files do not
map one-to-one to the two numbered PCAPs.

All January `conn.log` files, including nested `3/4`, `3/5` and `3/6` directories,
were inventoried by interval. Only `1/conn.log` overlaps this excerpt: 39,772
retained records, of which 39,768 are TCP/UDP. The raw scan encounters a packet
at the exact BRO start time for every one of those 39,768 TCP/UDP records. This
supports **zero additive clock offset between BRO and the supplied PCAPs**.
It does not prove that every packet of every BRO connection was captured.

For 39,768 BRO TCP/UDP rows, matching full tuples in either orientation with both
flow interval endpoints within one second yields 39,159 single candidates, 551
multiple candidates and 58 with none. Among single candidates:

- All 39,159 CSV start times agree with BRO start rounded to the nearest second.
- 38,945 CSV end times agree with similarly rounded BRO ends; 214 do not.
- 39,158 have the same original tuple orientation; one is reversed.
- Only 10,603 durations agree exactly at microsecond precision. Differences reach
  431,943 us, so CSV duration is not a substitute for the BRO packet interval.

All 2,992 retained GT rows have a coarse-interval full-CSV candidate. Seventy-three
have at least one candidate with a different family/normal label under the broad
bidirectional coarse join. These are ambiguity flags, not 73 proven bad GT rows.
The packet diagnostics find eight actual records with conflicting candidates.

The broad packet join uses a declared +/-1 second search tolerance for diagnostics.
It is **not a verified attack interval**. 21,666 raw records find GT candidates
only with this tolerance. Unknown boundary semantics, tuple reuse and conflicting
orientations remain excluded from accepted supervision. Matching uses protocol,
both IPs, both ports and time; neither source-IP-only nor destination-IP-only
matching is permitted. ICMP needs a separate type/code/identifier adapter.

The report's strike timestamps are relative seconds. For example, p542 lists the
Domino `/doladmin.nsf` reconnaissance strike at 30.1752644 seconds. Its name agrees
with GT row 2, but its absolute epoch origin is unverified. Do not add that value
to the first PCAP timestamp or use one strike to invent a universal clock offset.

## Packet-to-annotation witnesses

Packet numbers below are one-based within their original files. GT/BRO references
are physical source lines, including headers; full-flow and Argus CSVs have no
header. The linked JSON includes exact timestamps, byte offsets, packet hashes,
source hashes, all candidate rows and final exclusion reasons.

| Witness | Packet and time (Unix seconds) | Trace and decision |
| --- | --- | --- |
| Benign candidate | File 1 #24, `1421927414.035467` | UDP `59.166.0.5:3593 -> 149.171.126.5:53`; full CSV row 4 label 0; BRO line 14 UID `CczY8w3yJZI9n3C92g`; Argus row 7. Its reverse reply belongs to the same conversation. Normal candidate, not evidence that every silent second is normal. |
| Reconnaissance candidate | File 1 #14, `1421927413.887429` | TCP `175.45.176.0:13284 -> 149.171.126.16:80`; GT row 2; full CSV row 23; BRO line 10 UID `Ccas3O1rdOHyJpgOA4`; Argus row 5. Starts 112,571 us before integer GT start. Packet #22 at `1421927414.010311` lies inside its coarse interval. |
| Reverse direction | File 1 #18, `1421927413.906522` | SYN-ACK `149.171.126.16:80 -> 175.45.176.0:13284`; same GT/BRO conversation. This is server response involvement, not evidence that the server is the attacker. |
| Contradictory DoS candidates | File 2 #963084, `1421928708.199123` | UDP `175.45.176.3:7101 -> 149.171.126.16:53`; GT row 2483 and forward CSV row 34031 say DoS, reverse CSV row 34013 says benign. BRO line 32602 UID `Cpc9qE4QjTOQ60IIwe`. Exclude pending disambiguation. Reverse packet #963230 has the same conflict. |
| Unmatched normal-looking traffic | File 2 #883762, `1421928678.140326` | UDP `59.166.0.3:9000 -> 149.171.126.3:53`; BRO line 31906 UID `CHLFi32RHX2xUgszm3`; no GT/full-flow candidate within tolerance. Exclude as unknown even though it uses the normal pool and DNS port. |

Independent [tshark output](tshark_reconnaissance_anchor.csv) verifies the
reconnaissance packet timestamps, SLL directions, IP IDs, TTLs, TCP flags and raw
sequence numbers. For example, #14/#17 are receive/forward copies; #18/#19 are
the corresponding reverse copies. A later retransmission #316/#317 remains a
separate observed transmission. No malicious payload is executed.

## Candidate label coverage and exclusions

These are **candidate matches**, not packet-label accuracy or final supervised
coverage. Denominator: all 3,415,660 capture records, including paired views.
The primary categories below are mutually exclusive and sum to that denominator.
The second column subtracts only the identified forwarded copy in each pair;
its denominator is 1,708,290 retained observations, not proven unique events.

| Primary outcome | Raw records | After paired-copy subtraction |
| --- | ---: | ---: |
| CSV benign candidate | 3,233,390 | 1,616,699 |
| In-scope attack candidate: reconnaissance/DoS | 44,282 | 22,141 |
| Out-of-scope attack candidate | 136,803 | 68,405 |
| Conflicting candidates | 8 | 4 |
| No GT/full-flow candidate | 4 | 2 |
| ICMP adapter needed | 123 | 122 |
| Unsupported IPv4 protocol | 587 | 457 |
| ARP, outside current packet-label adapter | 442 | 442 |
| IPv4 fragments | 18 | 15 |
| Invalid/truncated declared IPv4 length | 3 | 3 |
| **Total** | **3,415,660** | **1,708,290** |

Raw GT family memberships before conflict exclusion are reconnaissance 3,986,
DoS 40,304, exploits 95,108, generic 8,682, shellcode 514, fuzzers 31,191, worms
1,158 and backdoor 150. Analysis has no candidate in this excerpt. These
memberships include the eight conflicts and must not be added to the primary
outcome totals. File-specific counts are in `packet_summary.json`; per-IP counts
are in `endpoint_observations.json`; role-group counts are in
`coverage_by_endpoint_group.json`. Endpoint incidences count both endpoints and
are deliberately not presented as independent packets or independent samples.

Across 38,080 observed endpoint-seconds, the provisional final-window categories
are 28,664 benign candidates, 1,720 positive candidates, 7,471 out-of-scope or
unresolved attack windows, 216 invalid observed-coverage windows, four conflicting
windows and five unknown windows. This diagnostic includes raw capture views and
partial edge seconds; it is not an accepted training-window table.

There are 1,617 complete wall-clock seconds in `[1421927377,1421928994)`.
For 34 monitored endpoints that is a potential grid of 54,978 endpoint-seconds:
38,059 have observed traffic and **16,919 are silent/unknown**. No normal idle
labels are filled. The two partial boundary seconds exclude 68 potential
endpoint-seconds; they are outside the complete-second denominator. At least the
first seven full seconds per endpoint are context-only before any eight-second
sequence can finish (238 potential final-window positions). Exclusions overlap
and must not be summed into a single loss percentage.

Verified supervised label coverage is **not established**, and zero supervised
sequences have been accepted or generated. A high diagnostic match rate does not
close the annotation or continuity gate.

## Final-window target and temporal contract

The target is **observed attack-connection involvement for the monitored endpoint
in the final one-second window**. It does not mean compromise, malicious intent
or attacker identity. A verified connection can contribute involvement in either
direction, including replies at the victim/server endpoint. An endpoint can be
monitored without being an attacker.

For a sequence ending at boundary T, use eight aligned half-open windows covering
`[T-8s,T)`. Determine the target only from packets observed in `[T-1s,T)`.
The earlier seven windows supply context; they do not propagate an old attack
label into a currently quiet final window. Never label a whole file, all traffic
of an IP pool or the unobserved interior of a connection interval.

Apply the tested policy in `ids/datasets/label_policy.py` after source normalization:

1. Invalid capture/feature coverage or endpoint binding excludes the window.
2. Contradictory verified annotations exclude it; preserve all provenance.
3. Any out-of-scope attack excludes it, including mixed-scope windows.
4. An unambiguous reconnaissance/DoS observation makes it positive; additional
   unknown traffic is recorded without erasing that positive evidence.
5. Benign requires documented normal coverage for all relevant observed traffic,
   valid capture/binding and no unknown packets. Idle normal requires additional
   healthy-capture and normal-coverage evidence; silence alone is insufficient.
6. All other windows remain unknown and excluded.

Normalize verified source intervals to half-open boundaries explicitly. The
inclusive, padded diagnostic search in this audit is not that normalization.
Preserve original timestamps, units, packet index/hash, BRO UID, GT/flow rows,
source group and mapping revision. Reset context at unverified discontinuities,
mapping changes or large clock regressions. Never join the excerpt to another
file solely because its filename number is next.

## Partition feasibility

There is **one connected source group**. The two files cannot be assigned to
different independent subsets. No independent three-way or four-way partition,
and no separate independent threshold subset, is feasible from the supplied
excerpt. Hashes and provider date folders do not manufacture session independence.

The preferred design remains whole-group train/validation/internal-test near
60/20/20. If enough independently supported groups later exist, reserve
60/10/10/20 for train/model-selection validation/threshold-only validation/internal
test. Every scored subset needs usable normal and attack support; source-group
membership and duplication constraints take priority over percentages.

For a disclosed within-session pilot only, the concrete chronological proposal is:

| Proposed role | UTC interval, half-open | Seconds before exclusions |
| --- | --- | ---: |
| Train | 11:49:37–12:05:47 | 970 |
| Validation | 12:05:47–12:11:10 | 323 |
| Internal test | 12:11:10–12:16:34 | 324 |

These ranges are not assigned training data. The two boundaries cross at least
10 and 22 BRO connections respectively; their UIDs and source rows are retained
in `partition_proposal.json`. Purge each crossing connection on both sides, all
endpoint windows touched by its packets and every sequence using those windows.
Also check Argus/GT/packet-only connections. Restart history at each boundary;
the earliest right-side sequence has exclusive end `B+8 seconds`. A seven-second
context guard alone does not prevent long-connection leakage. Keep both endpoint
views and all capture copies together. Recompute class/duration support after
purges before claiming even within-session evaluation feasibility.

The threshold-only reserve is not carved from this short validation range.
No preprocessing, score calibration or threshold fitting has occurred. The
prepared CSV train/test split is not a temporal substitute; the earlier CSV audit
also found repeated rows across those sets.

## What remains, and what does not need downloading now

The manifests and endpoint map that were previously requested from the user are
now prepared from available evidence. Matching GT, full CSVs, BRO/Argus files and
reports are already present. There is no request to download those again, create
synthetic replacement PCAPs or download the remaining 78 capture files now.

The unresolved facts are recorded with honest unknowns: original unique session
identifiers; exact original filename/acquisition mapping; physical capture
interfaces and loss counters; globally valid GT rounding/end rules; conflicting
and unmatched conversation labels; normal coverage for idle periods. Some are
intrinsic limitations of the supplied distribution rather than files the user
can manufacture. A later adapter can accept only independently supported joins
and exclude uncertain windows; it must not fill unknown provenance with guesses.

Additional independent source groups may be needed for a defensible evaluation.
Adjacent January chunks can extend coverage but remain linked to the same source
collection. A small separately audited February excerpt is a possible additional
source group to investigate later; no particular filename is promised to contain
adequate classes or to provide session independence before inspection. Even all
80 files do not automatically provide three independent sessions.

## External adapters

CSE-CIC-IDS2018 and BoT-IoT remain separate, **not packet-validated** adapters
because their captures/annotations were not supplied. The independent
[adapter audit](../../../docs/phase1_external_adapters.md) was rechecked against
their provider documentation. Neither inherits this UNSW clock, endpoint map,
tuple orientation or capture-view rule. No external predictions, scores,
thresholds or tuning were used. February UNSW source logs in the inventory are
still UNSW material, not an external evaluation dataset.

## Reproduction

Run from the repository with Python 3.12 or newer. The audit scripts use the
standard library. PDF reading/rendering used installed `pypdf`, `pypdfium2` and
Pillow; independent packet checks used local Wireshark 4.6.9. No source binaries
from downloaded datasets were executed.

First create a copy of `config.json` with a **new output directory**, preserving
the capture paths and scope. Keep the original audit directory as evidence.

```powershell
python scripts/prepare_phase1_sources.py --data-root "C:\Users\aayus\datasets-aisoc" --report "C:\Users\aayus\Downloads\report 22-1-2015.pdf" --csv-root CSV-Files --output experiments/phase1/raw-reproduction
python -m ids.datasets.packet_audit --config path-to-new-config.json
python scripts/audit_capture_views.py --config path-to-new-config.json
python scripts/complete_phase1_audit.py --config path-to-new-config.json
```

Generate the independent capinfos reference in the new directory before the
evidence check. Use numeric epoch timestamps rather than display-local time:

```powershell
& "C:\Program Files\Wireshark\capinfos.exe" -M -S "C:\Users\aayus\datasets-aisoc\pcap files\22-1-2015_1.pcap" "C:\Users\aayus\datasets-aisoc\pcap files\22-1-2015_2.pcap" | Set-Content -Encoding utf8 experiments/phase1/raw-reproduction/capinfos.txt
python scripts/check_phase1_evidence.py --output experiments/phase1/raw-reproduction --archive-root "C:\Users\aayus\datasets-aisoc"
python -m unittest tests.test_dataset_audit tests.test_packet_audit -v
```

Validation covers the parser, microsecond preservation, incomplete-record rejection,
fragments, nested BRO discovery, bidirectional matching, conflicts and final-window
label-policy behavior. Fifteen tests pass. The artifact check independently reads
saved packet offsets back from the original PCAPs and verifies their timestamps
and SHA-256 (39 complete witnesses), checks source-hash references and reconciles
count denominators. The nested BRO directories have zero overlap with this
excerpt; adding their inventory did not change the packet results.
Report interpretation and page-derived topology remain explicitly reviewed facts,
not a claim that an automated PDF parser can certify the dataset.
