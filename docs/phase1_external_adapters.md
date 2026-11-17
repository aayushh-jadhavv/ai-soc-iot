# Independent external adapter audit

Status rechecked on 17 November 2026: neither CSE-CIC-IDS2018 nor BoT-IoT raw traffic or
annotation tables are supplied. The local BoT-IoT README image is attribution
material only. These are independent adapter specifications with **NOT VALIDATED**
status, not completed packet audits. Neither borrows UNSW clock offsets, address
roles, tuple conventions, label scope or continuity assumptions.

The newly supplied January UNSW captures do not change either external adapter's
status. The November 17 source inventory and official documentation review were
performed without external predictions or model scores.

## CSE CIC IDS2018

The official documentation describes packet traffic, host logs and CICFlowMeter
features, with attack schedules and infrastructure details. These are sources to
obtain, not proof of a local sample's labeling.
Source: [UNB CSE CIC IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html).

Obtain a selected original day/host capture with all adjacent chunks, matching
host logs, attack schedule, original label/flow records and topology map. Preserve
original host/capture IDs, hashes and day grouping. Inspect the delivered schema;
verify date order, timezone/DST, epoch and duration units, rounding and clock offset
from packet anchors. Do not copy UNSW's candidate epoch-seconds interpretation.
Confirm flow direction/ports and internal, public or translated endpoint addresses.

Match full connection identity, time and both directions, disambiguated by host
and session. A schedule is a candidate interval; it does not label unrelated
traffic, all packets to a victim or every host that day. Missing tuples must come
from original records. Independently verify normal coverage, idle periods, tuple
reuse, clocks, unsupported traffic, truncation and duplicate host/network views.
Freeze class mappings and scope before seeing external performance.

Acceptance needs actual forward/reverse/benign/conflicting packet traces plus
per-day/host/family coverage and exclusions. All are currently unmeasured; no
adapted rows or sequences are produced.

## BoT IoT

The provider describes PCAP, Argus and CSV sources, a sampled 5% flow subset and
files organized by attack category/subcategory. Source:
[UNSW BoT IoT](https://research.unsw.edu.au/projects/bot-iot-dataset).

Obtain original PCAP chunks, corresponding labeled Argus/CSV records and topology/
timing records. Independently map protocol, both endpoint addresses/ports,
start/end times, category and subcategory. Inspect numeric/hex ports and non-port
protocols. Confirm timestamp precision, offset, interval endpoints, direction and
monitored endpoint membership using actual packets and provenance.

Category filenames are organization metadata. Do not label a whole file or infer
that every endpoint is malicious. The 5% subset cannot establish complete capture,
normal background, idle seconds or contiguous device history. Rejoin full records
and captures before temporal use. Audit duplicate capture views and repeated flows
independently from UNSW; group continuations and both endpoint views together.

Acceptance needs the same trace categories and coverage/exclusion denominators
by original capture/category/endpoint group. All are unmeasured. The local README
says academic use is free and commercial use prohibited; the current provider
page says commercial use requires agreement. Retain applicable distribution terms
and acquisition provenance. No commercial permission is asserted.

## Separation from development

Maintain independent source manifests and normalization configurations. Adapter
review may inspect labels and a declared diagnostic packet subset to validate
units, identities and joins; it may not run a model or choose settings from
external accuracy, recall, loss or scores. Adapter corrections require source
semantics and packet evidence.

No external score is computed. Reserve full external evaluation until weights,
preprocessing, scope and threshold are frozen from UNSW development. If external
results later inform any model or threshold change, reclassify them as development
and obtain new untouched external evidence. Do not merge external coverage with
UNSW or claim external validation from synthetic policy tests.
