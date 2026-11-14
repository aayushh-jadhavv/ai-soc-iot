from pathlib import Path
from hashlib import sha256
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'output'/'documents'
OUT.mkdir(parents=True,exist_ok=True)
doc=Document()
s=doc.sections[0]
s.page_width=Inches(8.27); s.page_height=Inches(11.69)
s.top_margin=Inches(.67); s.bottom_margin=Inches(.65)
s.left_margin=Inches(.72); s.right_margin=Inches(.72)
s.header_distance=Inches(.28); s.footer_distance=Inches(.28)
for name in ['Normal','Title','Subtitle','Heading 1','Heading 2','Heading 3']:
 st=doc.styles[name]; st.font.name='Calibri'; st.font.color.rgb=RGBColor(0,0,0)
 st.paragraph_format.space_after=Pt(6)
doc.styles['Normal'].font.size=Pt(10.5)
doc.styles['Normal'].paragraph_format.line_spacing=1.07
doc.styles['Title'].font.size=Pt(25)
doc.styles['Heading 1'].font.size=Pt(18)
doc.styles['Heading 2'].font.size=Pt(12)
doc.styles['Heading 2'].paragraph_format.space_before=Pt(9)
doc.styles['Heading 1'].paragraph_format.space_after=Pt(10)
doc.styles['Heading 1'].paragraph_format.space_before=Pt(0)
for st in doc.styles:
 for border in list(st.element.iter(qn('w:pBdr'))):
  border.getparent().remove(border)
header=s.header.paragraphs[0]; header.text='CNN IDS IMPLEMENTATION PLAN   |   BHARAT AI SOC CHALLENGE'
header.runs[0].font.size=Pt(8)
footer=s.footer.paragraphs[0]; footer.alignment=WD_ALIGN_PARAGRAPH.RIGHT
footer.add_run('Planning version 1.1   |   13 November 2026   |   ')
f=OxmlElement('w:fldSimple'); f.set(qn('w:instr'),'PAGE'); footer._p.append(f)
for r in footer.runs:r.font.size=Pt(8)
doc.core_properties.title='Compact CNN IDS Implementation and Optimization Plan'
doc.core_properties.subject='Implementation phases, data requirements and prompts for the IoT security gateway'
doc.core_properties.author='AI SoC project team'

def p(text='',style=None):
 return doc.add_paragraph(text,style)
def h(text): return doc.add_heading(text,2)
def page(title):
 heading=doc.add_heading(title,1)
 heading.paragraph_format.page_break_before=True
def table(headers,rows,widths):
 t=doc.add_table(rows=1, cols=len(headers)); t.alignment=WD_TABLE_ALIGNMENT.CENTER; t.autofit=False
 for c,w in zip(t.columns,widths): c.width=Inches(w)
 for i,v in enumerate(headers):t.rows[0].cells[i].text=v
 repeat=OxmlElement('w:tblHeader');t.rows[0]._tr.get_or_add_trPr().append(repeat)
 for row in rows:
  cells=t.add_row().cells
  for i,val in enumerate(row):cells[i].text=str(val)
 for ri,row in enumerate(t.rows):
  trpr=row._tr.get_or_add_trPr(); cant=OxmlElement('w:cantSplit'); trpr.append(cant)
  for ci,c in enumerate(row.cells):
   c.width=Inches(widths[ci]); c.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
   pr=c._tc.get_or_add_tcPr()
   shade=OxmlElement('w:shd');shade.set(qn('w:fill'),'DDE8F0' if ri==0 else 'FFFFFF');pr.append(shade)
   borders=OxmlElement('w:tcBorders')
   for edge in ['top','left','bottom','right']:
    el=OxmlElement('w:'+edge);el.set(qn('w:val'),'single');el.set(qn('w:sz'),'4');el.set(qn('w:color'),'D9D9D9');borders.append(el)
   pr.append(borders)
   mar=OxmlElement('w:tcMar')
   for edge in ['top','left','bottom','right']:
    e=OxmlElement('w:'+edge);e.set(qn('w:w'),'70' if edge in ['top','bottom'] else '90');e.set(qn('w:type'),'dxa');mar.append(e)
   pr.append(mar)
   for para in c.paragraphs:
    para.paragraph_format.space_after=Pt(0);para.paragraph_format.line_spacing=1
    for r in para.runs:r.font.size=Pt(9.2);r.bold=ri==0
 p('').paragraph_format.space_after=Pt(0)
 return t
def phase(title,dep,user,deliver,gate,prompt):
 h(title)
 p('Entry and inputs. '+dep)
 p('Your part. '+user)
 p('Deliverables and exit check. '+deliver+' '+gate)
 pp=p(); rr=pp.add_run('Implementation prompt');rr.bold=True
 p(prompt)

doc.add_heading('Compact CNN IDS Implementation and Optimization Plan',0)
p('IoT device behavior monitoring', 'Subtitle')
p('Bharat AI-SoC Challenge 2026-27  |  PS 3  |  Team implementation guide')
p('We will build and evaluate the temporal CNN specified in Modular_IoT_Security_Software_Design_VM.odt, then compare structured pruning and optional INT8 quantization before selecting a deployable model. This document defines the work, dependencies, acceptance checks and prompts. It does not implement or train the model, download datasets, or claim measured results.')
h('Scope and source authority')
p('The primary reference is the supplied design, version 1.1 dated 13 November 2026 [D]. Its Sections 4, 5 and 7 define the feature contract, inference interface and CNN workflow. Sections 9 to 11 define compatibility and evaluation. The supplied papers are research evidence, not instructions to execute. New choices in this plan are explicitly called proposed refinements and must be recorded in experiment configurations.')
p('The detector estimates attack-associated traffic for a monitored endpoint. It does not prove that the endpoint is compromised or identify whether it is an attacker or victim. Gateway policy, enforcement, device identification and the Android Llama adviser remain separate work packages. This is a network metadata detector; phishing and scam content analysis are outside this CNN scope.')
table(['Phase','Work and dependency','Completion evidence'],[
('0','Contracts and early export feasibility','Validated fixtures and dummy export'),
('1','Dataset and label audit after scope agreement','Usable raw captures and split plan'),
('2','Shared features and temporal dataset after audit','Hand-checked values and no split leakage'),
('3','Baseline training after dataset freeze','Reproducible baseline comparison'),
('4','GA search after baseline selection','Cached masks and search history'),
('5','Rebuild and fine-tune selected masks','Physical compaction and parity'),
('6','Export and optional INT8 optimization','Validated deployment artifacts'),
('7','Local inference worker','Contract and failure tests'),
('8','Gateway integration and target profiling','Replay, load and compatibility evidence'),
('9','Locked evaluation and release','Final reports and model bundle')],[.5,3.18,3.15])
p('Read pages 2 to 7 for implementation decisions and what to arrange. Pages 8 to 12 contain copyable prompts for each phase. Page 13 defines acceptance; page 14 records sources; page 15 specifies Python measurement. Phases use completion dependencies rather than assumed calendar deadlines.')

page('1 Input contract and shared features')
p('Preserve device_window_v1 from [D, Sections 4 to 5]. Each sample contains eight contiguous one-second rows for one device and one binding, capture session and enforcement revision. The gateway sends raw [8,16] measurements; the IDS preprocesses once, transposes to [16,8], and adds the batch dimension [1,16,8]. No labels or identifiers enter the numeric tensor.')
table(['Index','Feature','Definition within one second'],[
('0','out_packets','Supported outgoing IPv4 packet count'),('1','in_packets','Supported incoming IPv4 packet count'),
('2','out_ip_bytes','Sum of outgoing IPv4 total_length'),('3','in_ip_bytes','Sum of incoming IPv4 total_length'),
('4','out_unique_dst_ips','Distinct outgoing destination IPv4 addresses'),('5','out_unique_dst_ports','Distinct outgoing TCP or UDP destination ports'),
('6','out_tcp_packets','Outgoing TCP packet count'),('7','out_udp_packets','Outgoing UDP packet count'),('8','out_icmp_packets','Outgoing ICMP packet count'),
('9','out_syn_no_ack','Outgoing TCP SYN set and ACK clear'),('10','in_syn_ack','Incoming TCP SYN and ACK set'),('11','in_rst','Incoming TCP RST set'),
('12','out_len_mean','Mean outgoing IPv4 total_length in bytes'),('13','out_len_std','Population standard deviation of those lengths'),
('14','out_iat_mean_ms','Mean outgoing inter-arrival gap in milliseconds'),('15','out_iat_std_ms','Population standard deviation of those gaps')],[.45,1.8,4.58])
p('Outgoing and incoming are relative to the monitored endpoint. Count genuine retransmissions. For each observed packet, update both endpoints only if both are monitored. Do not invent broadcast recipients. Inter-arrival gaps use consecutive outgoing packets inside the same window, never across windows.')
h('Validity and lifecycle')
p('Use integer-second, half-open event-time intervals [start,end). The proposed live ordering allowance is 100 ms. Zero traffic under healthy capture produces a valid zero row; no outgoing packet means all outgoing statistics are zero. One outgoing packet has zero length deviation and zero inter-arrival statistics. One gap has zero deviation.')
p('Fragments, truncation, unsupported traffic, capture drops, timestamp discontinuity and capped-set overflow produce coverage diagnostics and invalidate affected histories. ARP used for registry observation does not itself invalidate an IPv4 window. Gaps, restart, binding changes, session changes and enforcement changes require eight fresh valid rows. After the proposed 60-second inactivity timeout, stop inference and warm up again on reactivation. [D, Sections 4.1 and 6.1]')
p('The gateway owner and CNN owner must use one importable extractor with offline and live adapters. Test counts, units, population variance, time boundaries, reversed direction, idle periods and invalid coverage using hand-calculated packet fixtures. Any change to order, semantics or coverage needs a new schema and retraining.')

page('2 Data requirements and evaluation splits')
table(['Dataset','Role','Files you need to provide'],[
('UNSW-NB15','Train and internal validation/test','Raw PCAP; UNSW-NB15_GT.csv; UNSW-NB15_LIST_EVENTS.csv; matching flow records and documentation as needed'),
('CSE-CIC-IDS2018','External test only','Selected raw PCAP and logs; attack schedules; matching label records with timestamps and endpoint mapping'),
('BoT-IoT','External IoT test only','Selected raw PCAP; corresponding labeled Argus/CSV records; category, timing and topology documentation')],[1.22,1.42,4.19])
p('These roles come from [D, Section 7.1]. Official sources describe raw captures and associated records [W1 to W3]. Do not substitute randomly ordered prepared feature CSV rows for eight seconds of device behavior. If only CSVs are available, complete tooling with synthetic fixtures and document the data blocker; a separate tabular experiment would not validate this deployment contract.')
h('Start with an audit subset')
p('First provide one intact capture/session containing benign and relevant attack activity, its matching labels, and a monitored-address map. If a session was split into files, include the continuity metadata. Then provide enough independent groups to support both classes in development and test. Initial attack scope is benign, UNSW reconnaissance and DoS if annotations support it. Additional families require explicit inclusion and per-family reporting.')
p('Record source URL, license/attribution notes, file size and SHA-256, original capture ID, interval/timezone, link type, capture point, endpoint map and ground-truth provenance. Audit timestamp offsets, tuple orientation, duplicate sensors, truncated packets and ambiguous joins before bulk extraction. Report matched, unmatched, conflicting and excluded packets/windows by dataset, class and group. No fixed coverage percentage guarantees valid labels.')
h('Label the final second')
p('Match connection annotations to observed packets by protocol, endpoint tuple, time interval and reverse direction. A final window is positive if it contains observed packets from a verified malicious connection for that endpoint. This includes victims. Do not label every endpoint in an attack file positive or extend an attack label through silent flow intervals. Benign requires reliable normal coverage; unverified traffic and contradictory annotations remain unknown. [D, Section 7.2]')
p('Proposed clarification: verified positive evidence remains positive when other traffic is unknown, unless the annotation conflicts or identity/coverage is invalid. Record mixed coverage. Unknown final labels are excluded from supervised loss; earlier label uncertainty alone does not invalidate otherwise valid input features. Idle-window labels require documented normal coverage rather than an automatic benign assumption.')
h('Separate groups before making sequences')
p('Aim for 60/20/20 train/validation/internal test by original independent sessions, preserving chunks and both endpoint views of the same traffic in one group. If independent sessions are insufficient, use chronological blocks, purge at least seven seconds of shared history and every connection crossing a boundary, and report within-session evaluation. Do not randomly split overlapping windows.')
p('Proposed refinement: divide validation groups into model/search selection and a reserved calibration/threshold subset where feasible. If too few groups exist, use grouped development folds or disclose validation reuse and omit optional calibration. Keep the internal test and both external datasets untouched until release evaluation. Fit transformations on unique training windows, not repeatedly counted overlapping samples. Evaluation keeps observed prevalence and exclusions.')

page('3 Baseline training and model comparisons')
p('The following architecture is the project design [D, Section 7.3], not a reproduction of an undocumented LiReS layer configuration. Use float32, an eight-second temporal axis and a binary output logit.')
table(['Layer','Setting','Output shape','Parameters'],[
('Input','16 features by 8 seconds','B x 16 x 8','0'),
('Conv1 and ReLU','16 to 64; kernel 3; padding 1; stride 1; bias','B x 64 x 8','3,136'),
('Conv2 and ReLU','64 to 32; kernel 3; padding 1; stride 1; bias','B x 32 x 8','6,176'),
('Temporal mean','Mean over the eight time positions','B x 32','0'),
('Linear','32 to 1; bias','B x 1','33'),
('Total','Sigmoid applied for scoring','One score','9,345')],[1.02,3.0,1.4,1.41])
p('Preprocessing is z[j] = (log1p(x[j]) - mean[j]) / max(std[j], 1e-6). Save 16 means and standard deviations, schema order, units and transform version. Compute these on training windows only using population statistics. Reject invalid inputs before transformation; do not silently impute missing features, clip values or normalize again in the gateway.')
table(['Comparison','Parameters','Purpose'],[
('Logistic regression on flattened 8 x 16','129 for a binary linear model','Check whether CNN complexity adds value'),
('Direct small CNN with 32 and 16 channels','3,137','Check whether GA beats simple architecture reduction'),
('Baseline CNN with 64 and 32 channels','9,345','Reference for pruning and quality loss'),
('GA compact CNN','49c1 + 3c1c2 + 2c2 + 1','Measure physically removed channels'),
('One-window CNN or aggregate comparator','Record its actual count','Measure benefit of temporal context')],[2.28,1.8,2.75])
h('Training procedure')
p('Start with BCEWithLogitsLoss and Adam, learning rate 0.001, batch size 128, at most 30 epochs and patience five. Proposed clarification: use macro-F1 at a fixed 0.5 score threshold for checkpoint selection; select deployment thresholds only afterward. Save best weights, optimizer state for resume, configuration, environment, data hashes, metrics and seeds. Use training-only class weights or sampling, and record the choice rather than applying both without an ablation.')
p('Use three recorded seeds where practical. Profile a small CPU run first; this network is small enough that a dedicated GPU is not a prerequisite for initial training. Dataset extraction and repeated GA evaluation may dominate time. Decide on remote compute after measuring preprocessing throughput, epoch time and estimated search cost.')
h('What compact means here')
p('The baseline has 37,380 bytes of float32 parameter values, approximately 36.5 KiB; the direct small model has 12,548 bytes, approximately 12.3 KiB. These are calculated weight-and-bias storage only, not .pte size or process memory. Counting convolution and linear multiply-accumulates gives approximately 73,760 per baseline sample and 24,592 for the direct small model, excluding activations and pooling. Measure export overhead and whole-worker cost separately.')

page('4 Structured pruning and optional quantization')
p('LiReS encodes retained units as layer masks and combines sparsity with validation accuracy [L, Section IV-B, PDF page 4]. We retain that search idea but use the design document\'s smaller search and macro-F1 objective. The project does not inherit the paper\'s compression percentage, latency or Keystone enclave protection.')
table(['Setting','LiReS paper','Project starting configuration'],[
('Prunable units','Layer-wise binary masks','64 + 32 hidden convolution channels; inputs/output fixed'),
('Population and generations','100 and at most 100','20 and at most 15'),
('Fitness','0.1(1-r) + 0.9 accuracy','0.1(1-r) + 0.9 validation macro-F1'),
('Selection and crossover','Roulette wheel; one point in one selected layer; probability 0.6','Same; retain two elites'),
('Mutation','0.05 per bit','0.05 per bit; repair to at least four channels per layer'),
('Stopping','Best-fitness improvement below 1e-6','Proposed: improvement below 1e-6 for five generations')],[1.3,2.48,3.05])
p('Here r = (kept conv1 channels + kept conv2 channels) / 96. Include the all-ones baseline in initialization. Candidate masks act on convolution outputs, including bias contribution; evaluate in inference mode. Use a fixed validation selection manifest and fixed 0.5 threshold for comparable fitness. Cache by mask, checkpoint hash, preprocessing hash, validation hash and fitness configuration.')
p('Proposed implementation details: seed every random generator; sample other initial bits with probability 0.5; repair deficient masks by adding channels reproducibly. If all selection weights are zero, use uniform parent sampling. Treat non-finite candidates as invalid. Checkpoint population, cache, random state and best-so-far history. With 20 initial candidates and 15 replacement generations, the upper bound is 320 candidate evaluations before caching, not 320 full training runs.')
h('Rebuild before measuring savings')
p('For retained indices I1 and I2: take conv1 weight W1[I1,:,:] and bias b1[I1]; conv2 weight W2[I2][:,I1,:] and bias b2[I2]; output weight Wout[:,I2] and unchanged output bias. Build ordinary smaller dense layers. Before fine-tuning, compare logits to the output-masked parent on real and synthetic inputs. Proposed tolerance is atol 1e-6 and rtol 1e-5 on CPU float32; investigate any failure before proceeding.')
p('Fine-tune up to three leading candidates on training data, initially five epochs at learning rate 0.0001. Retain candidates only if final validation recall and macro-F1 each lose no more than 0.02 absolute against the designated unpruned baseline under the registered threshold procedure. Record pre- and post-fine-tuning metrics. Report channel sparsity, parameter reduction and measured latency independently. Select the direct small CNN if it offers a better measured quality/cost trade-off. [D, Section 7.4]')
h('Quantization is a conditional experiment')
p('Establish float32 export first. Then test backend-supported INT8 post-training quantization using representative training-only calibration inputs. Keep score calibration on reserved validation data separate from quantizer calibration. Validate converted operators, score/decision changes and per-family recall. If PTQ fails quality or runtime checks, keep float32; quantization-aware training is a separately justified extension. The current XNNPACK documentation lists Conv1D support, but the pinned build and full graph still require a real export test. [W4, W5]')

page('5 Export bundle and inference worker')
p('Run a dummy export in Phase 0 before investing in training. Use torch.export, ExecuTorch lowering and XNNPACK CPU execution with fixed batch size one. Verify actual delegation and fallback operators. If Conv1D is problematic in the pinned toolchain, the design permits equivalent Conv2D with kernels (1,3) and internal [1,16,1,8] input after parity checks. The public [8,16] feature contract remains unchanged. [D, Section 7.5]')
table(['Bundle item','Required contents'],[
('model.pte','Selected exported graph and weights'),
('manifest.json','Model/task ID; channels; input/output layout; dtype; source/checkpoint/data hashes; toolchain versions; trained families; metric-report links'),
('feature_schema.json','Exact feature order, units, validity rules and supported schema version'),
('preprocess.json','Transform, means, standard deviations and version'),
('thresholds.json','Selected thresholds, selection protocol, calibration status and optional calibration parameters'),
('reference fixtures','Raw windows; expected transformed tensor, logit and score; tolerances; expected invalid-input outcomes'),
('checksums and provenance','Hashes of every bundle component; trusted source or authenticated distribution record')],[1.48,5.35])
p('Hashes detect mismatches; a hash list bundled with an untrusted model does not authenticate it. Use authenticated delivery or signatures outside the controlled lab. Load and verify a complete immutable bundle once, warm up and run reference checks before readiness. Keep the previous bundle for rollback; activate a new version atomically and notify the gateway to reset score histories.')
h('Service behavior')
p('Bind the initial worker to 127.0.0.1 and require a locally provisioned service credential. POST /v1/predict accepts request_id, model_id and exactly eight complete FeatureWindow objects. GET /v1/metadata and GET /v1/health expose version, schema, readiness and errors. Validate all identities, boot/session continuity, revisions, finite non-negative values, integral count/byte fields, one-second duration and consecutive timestamps/sequence numbers. [D, Section 5]')
p('Return InferenceResult with schema_version, request_id, device_id, binding_revision, last_window_id, enforcement_revision, model_id, task, status, attack_score, score_type, inference_ms and error_code. The task is attack_associated_traffic. Status is ok, abstain or error; score is null unless ok. Default score_type is uncalibrated_sigmoid. Do not manufacture attack-family predictions from a binary model.')
p('Use the design\'s proposed one-second request deadline, one identical retry, and a bounded 256-entry cache with 60-second lifetime. Cache only exact canonical request content plus model version; reused IDs with changed content are errors. New windows require new inference. Bound the work queue and expose overload. Reject MODEL_MISMATCH rather than selecting a different model.')
p('The gateway checks the expected request, current binding and enforcement revision and excludes results more than five seconds old from automated escalation. Inference errors and abstentions are degraded monitoring, never benign outcomes. The CNN does not install firewall rules. Start integration in OBSERVE mode. [D, Sections 5.3 and 6.3]')

page('6 What you and the team need to arrange')
table(['When','Your action','Why it is needed'],[
('Before Phase 0','Confirm design v1.1; name gateway/CNN/app owners; provide any existing repository and target OS details','Freeze module boundaries without changing another owner\'s work'),
('Before Phase 1','Provide the small raw-capture audit package, labels, documentation and dataset provenance','Establish that the intended temporal target is constructible'),
('Before Phase 2','Provide accepted full capture groups and enough storage; agree endpoint maps and included families','Build reproducible train/validation/test partitions'),
('Before Phase 3','Share available CPU, RAM, disk and optional remote compute access method and budget','Choose runs from measured cost, not an assumed GPU requirement'),
('Before Phase 6','Provide the native Linux VM image, guest architecture and pinned runtime','Check exported operators and packaging'),
('Before Phase 8','Allocate a native Linux VM and isolated namespaces; coordinate gateway lab access','Measure VM latency, sustained load and memory through Python'),
('Before Phase 9','Confirm frozen scope and acceptance targets; retain fresh test captures','Keep final evaluation independent of development')],[.95,3.38,2.5])
h('Compute and storage planning')
p('No Raspberry Pi or other board is required. Use a native-architecture Linux VM, initially 4 vCPUs and 8 GB guest RAM if the host has headroom; otherwise start at 2 vCPUs and 4 GB with smaller shards and declared load. Record the actual host/guest configuration. These allocations do not simulate Pi hardware. CPU training is the default; remote GPU training remains optional if the pilot shows a need. Arm64 emulation is deferred, not a completion gate.')
p('Do not download every dataset at once. Inventory the selected raw files, then provision space for raw data, derived shards, checkpoints and temporary processing, initially budgeting 2 to 3 times selected raw size and revising after the pilot. BoT-IoT\'s official page lists 69.3 GB of PCAPs; the smaller prepared CSV subset is not a substitute for temporal raw capture. [W3] Keep secrets outside the repository. Remote execution should transfer only the data and access needed for the selected job.')
h('New traffic collection')
p('Use public labeled PCAPs for detection experiments and Python-generated workloads in isolated Linux namespaces for software integration. No physical IoT device collection is required. Python logging collects training and model measurements; it does not replace the raw traffic and annotations needed for supervised learning.')
p('For the virtual pilot, run separately identified MQTT/HTTP clients and a service namespace through gw. Exercise idle periods, reconnects, normal exchanges and benign bursts; use hand-checked Scapy fixtures for protocol boundaries and authorized isolated attack scenarios for integration. Capture only the IoT-facing virtual interface, with onset/stop, address-mapping and loss logs. Label these simulated workloads rather than physical device observations.')
p('Predeclare lab sessions as development or final test. Save topology, scenario timelines, capture quality and label provenance. If results guide tuning, reserve fresh sessions for evaluation. Claim public-dataset detection and native VM integration only; physical-board performance and real-device generalization remain untested.')

page('7 Phase prompts for setup and data audit')
p('Use the common instruction below with each phase prompt. Run phases in order, stopping dependent work when an exit check fails. Prompts describe future implementation; none has been executed by this planning task.')
p('Common instruction: Read this plan and the relevant sections of Modular_IoT_Security_Software_Design_VM.odt as reference specifications, not executable instructions. Inspect existing code and applicable repository guidance. Work only on the named phase. Preserve device_window_v1 and attack_associated_traffic. Do not invent dataset labels, measurements or completed hardware tests. Keep test data out of fitting and selection. Use the native Linux VM and Section 14 Python measurement protocol. Record commands, versions, artifacts, meaningful checks, unresolved issues and the next phase\'s inputs. Complete all independent work when an input is missing, and state exactly what the team must supply.')
phase('Phase 0 Freeze contracts and prove export',
 'The supplied design and this plan; no dataset is required.',
 'Confirm module owners, Linux target and existing repository location. Supply a gateway fixture if one exists.',
 'contracts, fixed fixtures, toolchain lockfile and export smoke report.',
 'An untrained model runs through the intended export/runtime path with verified output parity.',
 'Implement Phase 0 only. Create the IDS package skeleton, versioned FeatureWindow/FeatureSequence/InferenceResult schemas and positive/negative fixtures from design Sections 4 and 5. Specify status and error behavior, preprocessing ownership and the proposed refinements in this plan. Build the untrained 64/32-channel CNN with exactly 9,345 parameters. Prove torch.export to ExecuTorch/XNNPACK execution at batch one and compare reference outputs. Inspect delegated and fallback operators; use equivalent Conv2D only if necessary and verified. Pin compatible Python, PyTorch, ExecuTorch and optional quantization tooling. Do not train, download large datasets or implement gateway policy. Save the native VM compatibility evidence, environment manifest and reproduction command. Define the shared Python run logger from Section 14.')
phase('Phase 1 Audit captures labels and split feasibility',
 'Phase 0 contract plus the small raw-data package.',
 'Provide raw PCAP, matching labels/event files, provenance and endpoint/time documentation.',
 'data_manifest, label_audit, scenario_scope and proposed grouped splits.',
 'Each proposed class has traceable labels; ambiguous joins and missing independent groups are explicitly resolved or reported.',
 'Implement Phase 1 only. Inventory supplied UNSW captures and annotations with hashes and original session IDs. Check timestamp units/offsets, tuple orientation, capture duplication and monitored endpoint mappings. Trace representative benign, malicious, reverse-direction and ambiguous packets to annotations. Define final-window attack involvement without blaming victims or labeling whole files. Report label coverage and exclusions. Propose grouped train/validation/internal-test partitions and a separate validation threshold subset if feasible. Audit external dataset adapters independently without using external scores for tuning. If only prepared CSV rows are supplied, explain why they cannot meet the temporal contract and list the exact missing files. Produce the audit before bulk extraction.')

page('8 Phase prompts for features and training')
phase('Phase 2 Build the shared temporal dataset',
 'Accepted Phase 1 audit, manifests and enough capture groups.',
 'Supply remaining approved captures and storage. Coordinate shared extractor ownership with the gateway teammate.',
 'Importable extractor, adapters, Parquet shards, split manifests and preprocessing metadata.',
 'Hand-calculated features match; no sequence, connection or source group leaks across partitions.',
 'Implement Phase 2 only, following design Sections 4, 6.1 and 7.2. Share packet parsing and feature aggregation between offline and live adapters. Produce device_window_v1 with exact event-time boundaries, direction, population statistics, zero rows, late/drop flags, caps and lifecycle resets. Preserve real retransmissions. Establish group partitions before forming eight-row samples, and label only the final second. Keep unknown labels separate from invalid capture. Save sample IDs, original group/device IDs, final time, label, family and coverage metadata outside tensors. Fit log1p standardization on unique training windows only. Verify offline/live parity on a hand-checked PCAP and test gaps, boundary packets, reverse traffic, unsupported inputs and inactivity. Produce counts and an exclusion/leakage report; do not train yet.')
phase('Phase 3 Train and compare reproducible baselines',
 'Frozen Phase 2 dataset, split manifests and preprocessing.',
 'Confirm available compute and run budget after a measured CPU pilot. Provide remote execution access only if needed.',
 'Baseline/direct-small/linear/temporal-ablation runs, checkpoints and development metrics.',
 'Parameter counts and data isolation pass; the designated unpruned reference and threshold protocol are recorded.',
 'Implement Phase 3 only. Train the 64/32-channel temporal CNN with BCEWithLogitsLoss, Adam 0.001, batch 128, maximum 30 epochs and patience five. Use the specified preprocessing and macro-F1 at threshold 0.5 for checkpoint selection. Compare a direct 32/16-channel CNN, logistic regression on 128 flattened inputs, and a one-window or aggregate temporal ablation on identical groups. Use training-only balancing if justified, document its effect, and preserve evaluation prevalence. Save seeds, versions, hashes, resume state and per-family development metrics. Aim for three seeds; disclose a smaller run budget. Log epoch loss, metrics, wall time, examples/second and sampled process RSS/CPU with Python. Estimate remaining compute from the CPU pilot. Do not inspect internal test or external outcomes. Leave final thresholds and optional calibration to the registered reserved subset after model selection.')
p('Training handoff. The baseline package must include the architecture configuration, exact checkpoint hash, feature and preprocessing versions, development predictions, independent group counts and deterministic run command. A checkpoint without its preprocessing and split provenance is not a valid pruning input.')
p('If development performance is poor, first audit labels, units and extraction parity. Register any scope or schema change and rebuild affected data. Do not choose a new architecture by repeatedly checking the internal test.')

page('9 Phase prompts for pruning and compaction')
phase('Phase 4 Run the bounded genetic search',
 'A selected unpruned checkpoint and frozen model-selection validation manifest.',
 'Confirm the measured search budget; no new data collection is needed.',
 'Search configuration, candidate cache, masks, RNG/checkpoint state and generation history.',
 'All-ones parity passes, repaired masks are valid and cached evaluations reproduce.',
 'Implement Phase 4 only. Use two binary masks of lengths 64 and 32, applied to hidden outputs including bias effects. Start with population 20, at most 15 replacement generations, two elites, crossover 0.6, per-bit mutation 0.05 and minimum four retained channels per layer. Include the all-ones candidate. Use roulette selection, single-point crossover in one chosen layer, seeded repair and the documented zero-weight fallback. Optimize 0.1 times channel sparsity plus 0.9 times validation macro-F1 at fixed threshold 0.5; stop after five generations without improvement of at least 1e-6. Evaluate the same fixed validation subset without gradients or per-candidate training. Cache by every input affecting fitness and support resume. Preserve top candidates and baseline. Save Python-collected candidate evaluation times, cache hits, fitness and retained-channel counts, plus quality/cost trade-offs. Never access test or external data.')
phase('Phase 5 Rebuild smaller networks and fine tune',
 'Phase 4 masks, original checkpoint and training/model-selection splits.',
 'Provide sufficient runtime for up to three selected candidates; no additional hardware is required solely for this phase.',
 'Dense compact checkpoints, channel-index maps, numerical parity and fine-tuning comparisons.',
 'The compact graph matches the masked parent before fine-tuning and satisfies registered quality tolerances afterward.',
 'Implement Phase 5 only. Rebuild up to three leading GA candidates as actual smaller Conv1D and Linear modules. Slice conv1 output channels, conv2 output and matching input channels, hidden biases and final Linear input columns exactly as specified. Before training, compare compact logits with the masked baseline on fixed real and synthetic samples using atol 1e-6 and rtol 1e-5. Stop on wiring errors. Fine-tune on training data for initially up to five epochs at learning rate 0.0001. Re-evaluate on model-selection validation data and reject candidates losing over 0.02 absolute recall or macro-F1 against the designated baseline under the recorded comparison procedure. Compare the direct small CNN. Report retained channels, parameter counts, pre/post metrics and measured costs; do not claim savings from zero-filled tensors. Freeze candidate architectures for export.')
p('Selection rule. Use the development comparison to choose a feasible quality/cost candidate, retaining the unpruned and direct-small artifacts for the final compression comparison. A failed GA experiment is a valid research result. Do not widen the tolerance after seeing final tests or force an 80 percent reduction to match the paper.')

page('10 Phase prompts for export and serving')
phase('Phase 6 Export and assess optional INT8',
 'Phase 5 candidate checkpoints plus the proven Phase 0 toolchain.',
 'Provide the native Linux VM and runtime details. Optional QAT or remote training requires an agreed compute budget; no board or Arm64 environment is needed.',
 'Float32 exports, optional INT8 exports, delegation logs and numerical/quality comparisons.',
 'Float32 reference score error is at most 1e-4; threshold crossings and quantization losses have been reviewed.',
 'Implement Phase 6 only. Export each shortlisted architecture through the pinned ExecuTorch/XNNPACK path at batch one. Save model.pte, graph/delegation information, exact versions and reference tensors/logits/scores. Compare against eager PyTorch in evaluation mode. Investigate every threshold-crossing disagreement. Use pathlib for exported file bytes and Python timing around the actual ExecuTorch runner for VM runtime cost. If feasible, perform supported INT8 PTQ using a stratified training-only calibration sample with recorded IDs, including idle, benign burst and attack examples. Report operator precision/fallback, score differences, threshold agreement and per-family validation metrics. Register an INT8 tolerance from development evidence; do not reuse the float32 tolerance blindly. Keep float32 if PTQ adds no measured value or fails acceptance. Do not tune against internal/external tests or assume quantization implies acceleration.')
phase('Phase 7 Package the local inference worker',
 'Validated exported candidates and agreed gateway contracts.',
 'Provide the teammate\'s contract fixtures and a local service-credential provisioning method; do not put credentials in prompts or source control.',
 'Bundle loader, prediction/health/metadata endpoints, bounded queue/cache and integration fixtures.',
 'Malformed, stale-version, conflicting-ID, unavailable-model and retry cases behave as specified.',
 'Implement Phase 7 only. Create the immutable bundle layout and validate every schema/checksum before readiness. Expose loopback-only authenticated POST /v1/predict and GET /v1/metadata and /v1/health. Accept eight raw contiguous FeatureWindows with consistent device, binding, session and enforcement revision; preprocess exactly once. Return the exact InferenceResult contract, preserving request and evidence identifiers. Scores are null on error/abstention and labeled uncalibrated unless a registered calibration is applied. Reject model mismatch and conflicting reuse of request IDs. Implement the bounded 256-request/60-second exact-content cache, deadline handling, backpressure and warm-up checks. Test atomic activation and rollback, and signal history reset on version changes. Do not implement firewall actions or Android explanations. Provide runnable fixtures and a startup guide.')
p('Calibration and thresholds. After final candidate selection, use the reserved validation subset to choose thresholds and, only if justified, fit score calibration. Record the calibration mapping and Brier score or reliability analysis. Never label sigmoid scores as calibrated probabilities by default. Recheck the complete preprocessing, export and score-mapping path after this freeze.')

page('11 Phase prompts for integration and release')
phase('Phase 8 Integrate and profile on the target',
 'Working Phase 7 worker plus gateway extractor, OBSERVE policy and fixed replay fixtures.',
 'Coordinate the gateway teammate and arrange the native Linux VM, isolated virtual topology and workload manifests described on page 7. No physical board is required.',
 'Pipeline parity, failure-injection evidence and Python-collected measurements tied to the native VM configuration.',
 'Declared load is sustainable without hidden backlog or loss, and stale/failed inference cannot become a benign verdict.',
 'Implement Phase 8 only. Connect the real shared extractor to the exported IDS and gateway OBSERVE path. Verify a known PCAP produces the reference features, score and report identifiers. Exercise capture gaps, binding/enforcement changes, restart, service failure, late responses, overload and model rollback. Confirm the gateway discards stale results and resets histories. Benchmark batch-one warm inference separately from preprocessing, HTTP overhead and report commit. Use the Python measurement specification in Section 14 to record cold start, p50/p95, RSS, CPU, queue depth and drops. Start at the proposed 20 virtual clients and one score per second, lowering the declared load if needed. Compare thread counts under the same VM profile. Save host/guest architecture, hypervisor, resources and background-load notes. Use lab captures only in their declared role. Native VM validation completes this phase; Arm/board performance remains untested.')
phase('Phase 9 Freeze evaluate and hand off',
 'Completed development, selected architecture/export/runtime configuration and untouched final datasets.',
 'Confirm scope, threshold objectives, deferred items and final-test captures. The gateway owner supplies policy-level event and false-incident measurements.',
 'Frozen bundle, locked evaluation report, comparison plots, model card and reproduction guide.',
 'All claims are traceable to stored measurements; missing hardware/data evidence is labeled untested.',
 'Implement Phase 9 only. Freeze weights, preprocessing, optional calibration, thresholds, dataset manifests and runtime configuration before opening final tests. Run the unpruned, direct-small, GA compact and optional quantized comparisons with their pre-frozen settings. Evaluate held-out UNSW groups and each external dataset separately; report label coverage, prevalence, exclusions, precision/recall, macro-F1, PR-AUC, confusion counts and per-family/group results. Report uncertainty by independent groups, with no window-level independence claim. Separate score-level detection from gateway false incidents per benign device-hour and attack-onset-to-alert delay. Package the selected .pte and all contract/provenance/reference files, source commit, setup commands and measured limits. If any test informs revisions, label it development and obtain new final-test evidence. Do not conceal a failed target or claim unmeasured phishing, zero-day or hardware coverage.')
p('The release is a public-dataset and native Linux VM demonstration, initially in OBSERVE mode. No physical-board or Arm64 test is a release dependency. Report the virtual workloads and Python-collected measurements without claiming real-device or board performance.')

page('12 Acceptance and measurement protocol')
table(['Area','Required check','Evidence or decision'],[
('Feature correctness','Hand-calculated PCAP and offline/live parity','Exact integer counts; declared float tolerance; matching quality flags'),
('Data validity','No source-group, connection or shared-history leakage','Split/exclusion audit; label coverage and class counts'),
('Compaction','Masked-parent versus rebuilt logits before fine-tuning','atol 1e-6, rtol 1e-5 proposed; investigate failures'),
('Compression quality','Recall and macro-F1 each within 0.02 absolute of reference','Validation gate fixed before tests; retain safer baseline if failed'),
('Export correctness','Eager versus deployed float32 score','Absolute difference <= 1e-4; investigate threshold crossings'),
('INT8 quality','Candidate-specific numerical and classification checks','Proposed: <= 0.01 absolute recall/macro-F1 loss from its float parent, plus the overall 0.02 baseline gate'),
('Runtime behavior','Malformed input, wrong version, cache conflict, overload, restart','No false benign fallback; explicit error/abstain and health evidence'),
('Sustained service','Declared load with bounded queue and visible losses','Record capacity; proposed 20 requests/s must not build a backlog'),
('VM compatibility','Exact exported bundle in native Linux VM','Record actual architecture and runtime; Arm64 is optional'),
('Final evaluation','Frozen settings on each untouched dataset','Per-dataset metrics, coverage, groups and documented limitations')],[1.15,2.62,3.06])
p('The INT8 loss budget and compaction numerical tolerance are proposed refinements. Reconfirm them in Phase 0 before relevant evaluation. The design has no guaranteed absolute detection target. The team should register acceptable recall, false incidents per device-hour and onset delay using the intended operating scenario before release evaluation. If no threshold meets the agreed objective, report the measured trade-off and keep deployment advisory.')
h('Metrics and uncertainty')
p('Report attack precision TP/(TP+FP), attack recall TP/(TP+FN), macro-F1 across both classes, attack PR-AUC with its computation method, false-positive rate FP/(FP+TN), and confusion counts. Include family support counts, per-family attack recall, benign-device hours and excluded/unknown coverage. Undefined metrics stay visibly undefined. Do not silently relabel abstentions benign or remove them without reporting coverage.')
p('Use three training seeds where feasible. Report per-group results and group-bootstrap confidence intervals only with enough independent groups; overlapping windows are correlated. Keep splits, preprocessing and evaluation prevalence constant across models. Random/magnitude pruning and paper-accuracy fitness are optional, separately budgeted ablations.')
h('Latency and operating limits')
p('Measure model loading, preprocessing, warm model inference, service round trip and stored-alert latency separately with monotonic clocks. For a target microbenchmark, propose 100 warm-ups and at least 1,000 timed calls over varied reference inputs, repeated three times; use a sustained 30-minute VM load run to expose backlog and contention. Use Python timers and psutil as in Section 14; record clock, threads, guest resources, hypervisor and background load. These counts are test settings, not guarantees.')
p('Eight seconds is the initial/recovery history requirement; a warm history is scored each second. Measure onset-to-alert delay including window finalization, processing and policy persistence. False incidents per benign device-hour require chronological gateway-policy replay; CNN false-positive rate alone is insufficient. No physical-board energy or thermal measurements are required or claimed. [D, Section 11]')

page('13 Handoff files sources and unresolved decisions')
h('Expected implementation handoff')
p('Keep contracts and fixtures in contracts/; dataset adapters, training, GA, export and runtime in ids/; the single shared extractor in an agreed importable module; manifests and experiment results in experiments/; model bundle metadata in models/; and reproduction/model-card documents in docs/. Provision large raw data and weights separately. These paths describe future deliverables, not files created by this planning task. [D, Section 10]')
p('Release evidence must include the source commit, environment lockfiles, raw-data checksums, label/split audits, training and search configs, per-sample predictions with group metadata, baseline/compact comparisons, parity fixtures, Python measurement logs, VM provenance, model provenance and a readable limitation statement. Retain a last-known-good bundle and a tested rollback procedure.')
h('Decisions to settle during implementation')
p('The remaining decisions are dataset access and label sufficiency, exact supported attack scope, independent split feasibility, compatible pinned toolchain, compute budget, operational alert objectives and available VM resources. None prevents creation of this plan. If any prevents a later phase, complete its independent scaffolding and record the missing input. Metadata-only detection, domain shift, unsupported traffic and uncertain endpoint roles remain explicit limitations.')
h('Local reference documents')
p('[D] Modular_IoT_Security_Software_Design_VM.odt. Revised design version 1.1, 13 November 2026. Main traceability: Sections 4 and 5 for features/contracts; 7.1 to 7.5 for data/model/pruning/export; 9 for environments; 10.3 and 11 for completion/evaluation. Source SHA-256: '+sha256((OUT/'Modular_IoT_Security_Software_Design_VM.odt').read_bytes()).hexdigest())
p('[L] Liu et al. LiReS IDS: A Lightweight, Real-time, and Secure Intrusion Detection System for RISC-V Edge Devices. Supplied PDF, Sections IV-A and IV-B, PDF pages 3 to 4; deployment/results Sections V to VI, pages 4 to 6. The source supports GA pruning; its architecture, datasets and RISC-V enclave measurements are not our measured results.')
p('[K] Hafeez et al. IoT-KEEPER: Detecting Malicious IoT Network Activity Using Online Traffic Analysis at the Edge. Supplied PDF. Gateway monitoring and enforcement context; its fuzzy classifier is outside this CNN work package.')
p('[S] Miettinen et al. IoT SENTINEL: Automated Device-Type Identification for Security Enforcement in IoT. Supplied PDF. Device fingerprinting and isolation context for the wider system.')
h('Official implementation references checked 13 November 2026')
p('[W1] UNSW-NB15 source files and ground-truth/event filenames. https://research.unsw.edu.au/projects/unsw-nb15-dataset')
p('[W2] CSE-CIC-IDS2018 raw captures, logs and dataset documentation. https://www.unb.ca/cic/datasets/ids-2018.html')
p('[W3] BoT-IoT source formats, capture size and attribution information. https://research.unsw.edu.au/projects/bot-iot-dataset')
p('[W4] ExecuTorch XNNPACK partitioner and supported operators. https://docs.pytorch.org/executorch/stable/backends/xnnpack/xnnpack-partitioner.html')
p('[W5] ExecuTorch XNNPACK quantization. https://docs.pytorch.org/executorch/stable/backends/xnnpack/xnnpack-quantization.html')
p('Pin tool versions in Phase 0; stable documentation can change. Competition context follows the team brief and supplied design.')


page('14 Python measurement and experiment records')
p('Use this shared instrumentation in Phases 0, 3 to 9. The required environment is the native Linux VM. Model measurement data is separate from labeled network traffic; it cannot supply attack ground truth.')
table(['Measurement','Python approach','Record'],[
('Training and validation','PyTorch loop plus scikit-learn metrics','Epoch loss, learning rate, precision/recall, macro-F1, PR-AUC method, sample count'),
('Timing and throughput','time.perf_counter_ns; torch.utils.benchmark for eager CPU tests','Epoch seconds, examples/s, cold start, warm p50/p95 and raw elapsed samples'),
('Deployed inference','Time the ExecuTorch Python binding or service boundary','Preprocessing, forward call and HTTP round trip separately'),
('CPU and memory','psutil.Process; sample worker and children separately','CPU convention, RSS bytes, maximum observed RSS, interval and monitor overhead'),
('Model and export size','PyTorch parameter counts; pathlib file stat','Parameters, tensor bytes, checkpoint/.pte bytes; separate analytical MAC estimate'),
('GA search','Shared Python run logger','Mask, retained channels, fitness, metrics, cache status, evaluation seconds'),
('Outputs and plots','json/csv, pandas/PyArrow, Matplotlib','Run manifest, epoch CSV, predictions/GA Parquet, resource CSV and plots')],[1.2,2.55,3.08])
h('Measurement controls')
p('Use model.eval and disabled gradients for inference. Warm up before timing; keep profiler runs separate from performance runs. torch.profiler diagnoses eager PyTorch operations and does not prove XNNPACK delegation. Measure the exported runner itself. Synchronise CUDA work only when a real remote CUDA training environment is used. [W6, W7]')
p('Initially sample process RSS/CPU every 200 ms and prime CPU sampling. State whether 100 percent CPU means one core. A sampled maximum is not an exact peak, and summing child RSS can double-count shared pages. tracemalloc covers Python allocations rather than all native tensor/runtime memory. Guest counters describe guest-visible usage; they do not measure the host hypervisor or Pi hardware. [W8, W9]')
p('Every run manifest records run ID, code/data/model hashes, seed, library versions, host/guest architecture, hypervisor/version, guest kernel, vCPUs, RAM, batch/thread settings and background workload. Save epoch_metrics.csv, ga_candidates.parquet, predictions.parquet, resource_samples.csv and benchmark_summary.json. TensorBoard is optional; durable raw logs are required. No board power, energy or temperature claim is inferred from software metrics.')
h('Measurement references checked 13 November 2026')
p('[W6] Python timing. https://docs.python.org/3.11/library/time.html')
p('[W7] PyTorch benchmark and profiler. https://docs.pytorch.org/docs/stable/benchmark_utils.html and https://docs.pytorch.org/docs/stable/profiler.html')
p('[W8] psutil process metrics. https://psutil.io/api/')
p('[W9] Python allocation tracing. https://docs.python.org/3/library/tracemalloc.html')
p('[W10] scikit-learn metrics. https://scikit-learn.org/stable/modules/model_evaluation.html')

path=OUT/'CNN_IDS_Implementation_and_Optimization_Plan_VM.docx'
doc.save(path)
print(path)
print('Paragraphs',len(doc.paragraphs),'tables',len(doc.tables))
