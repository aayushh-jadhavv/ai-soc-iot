from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
import re

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'output'/'documents'
T='urn:oasis:names:tc:opendocument:xmlns:text:1.0'
NS={'t':T}
src=ROOT/'Modular_IoT_Security_Software_Design.odt'
z=ZipFile(src); tree=E.fromstring(z.read('content.xml'))
def text(e): return ''.join(e.itertext())
def find(prefix):
 es=[e for e in tree.xpath('//t:p | //t:h',namespaces=NS) if text(e).startswith(prefix)]
 assert len(es)==1,(prefix,len(es))
 return es[0]
def change(prefix,value):
 e=find(prefix)
 for c in list(e):e.remove(c)
 e.text=value
def add_before(anchor,value,heading=False):
 e=E.Element('{'+T+'}h' if heading else '{'+T+'}p')
 e.set('{'+T+'}style-name','Heading_20_2' if heading else 'Standard')
 if heading:e.set('{'+T+'}outline-level','2')
 e.text=value; anchor.addprevious(e)

changes={
'The deployment target is a Raspberry Pi 5': 'The current implementation target is a native-architecture Linux virtual machine on the available computer, with CPU inference and a virtual routed IoT network. No Raspberry Pi or other development board is available or required. This reproduces the gateway software workflow, not Raspberry Pi 5 hardware. Android phones remain a separate app test environment. Arm64 emulation is an optional future compatibility experiment, not a completion requirement.',
'Version 1 design dated': 'Version 1.1 design dated 13 November 2026. This revision replaces board prerequisites with native Linux VM validation and adds Python-based experiment measurement. Numerical settings remain proposed starting values unless identified as paper settings. Freeze them in experiment configurations and adjust only using development data. No detection or performance results are claimed here.',
'Place the IoT access point or switch': 'In the current lab, place virtual clients downstream of the gw namespace, using isolated bridges and explicit routes. A host or VM joining an existing LAN does not automatically observe its traffic.',
'Ubuntu Server 24.04 LTS for the lab': 'Ubuntu Server 24.04 LTS in a native-architecture VM; record host and guest architecture',
'Arm checks': 'Optional future Arm check',
'linux/arm64 container under emulation': 'Deferred linux/arm64 userspace compatibility check; not required for this release',
'These are integration choices, not a claim': 'Pin PyTorch, ExecuTorch, export tooling, Python, Android dependencies, model and tokenizer versions after a minimal export-and-inference test. Record the VM image, kernel, architecture, hypervisor, resource allocation and lockfiles. Use XNNPACK CPU inference in the native VM; do not assume an x86 export has been validated on Arm. Collect model and training measurements through the Python instrumentation in Section 7.6. [S6, S7]',
'Figure 1 Runtime components': 'Figure 1 Runtime components and their contracts. In the current lab, virtual clients, Linux bridges and service namespaces represent the network nodes shown; the gateway kernel is the VM Linux kernel.',
'3.1 Reference routed deployment': '3.1 Reference routed virtual deployment',
'Use the following path for protected upstream communication.': 'Use the following path inside the native Linux VM. Section 9.1 defines the namespace topology; no physical board, access point or USB network adapter is required.',
'IoT devices -- IoT AP': 'Virtual IoT clients -- isolated IoT bridge -- IoT interface of gw',
'Pi routing and capture': 'gw namespace routing and capture in the Linux VM',
'Existing router ---------------': 'Service namespace -- isolated service bridge -- upstream interface of gw',
'For a physical Pi, use its Ethernet': 'Create two veth-backed gateway interfaces connecting separate IoT and service bridges. Configure clients to use gw as their IPv4 default router and configure the service return route. Start with static addresses; test DHCP through dnsmasq within the isolated lab if discovery is in scope. Do not run lab DHCP on the host ordinary LAN. A later physical deployment would need its own interface and attachment validation. [S12]',
'An existing all-in-one router': 'Keep the virtual traffic path explicit. Attach clients and services to different isolated Linux bridges, with no default container or host route bypassing gw. Connecting a VM to the normal LAN alone does not route other devices through it. A future physical Wi-Fi deployment would require a separate attachment and coverage review.',
'9 Building without the physical Raspberry Pi': '9 Native Linux VM implementation and validation',
'Use two environments with different purposes.': 'Use one required environment: a hardware-virtualised Linux VM matching the host CPU architecture. It runs the gateway, CNN worker and virtual network clients/services. No board or Arm64 guest is required. A native x86 VM executes x86 software; it does not emulate the Pi 5 CPU, peripherals or thermal behavior. Optional architecture emulation can be considered later and must be reported separately.',
'Use a native-architecture Ubuntu Server VM': 'Use a native-architecture Ubuntu Server VM, initially four vCPUs and 8 GB guest RAM only if the host can spare them. Otherwise start with two vCPUs and 4 GB guest RAM, smaller dataset shards and a reduced declared load. Record the actual allocation; these are resource profiles, not Pi-equivalent specifications. Keep the experiment network isolated from the ordinary LAN and preserve host memory headroom.',
'9.2 Arm compatibility environment': '9.2 Native VM measurement environment',
'First build a linux/arm64 application image.': 'Export and run the IDS bundle inside the native Linux VM using its actual CPU architecture. Record the host CPU/OS, hypervisor/version, guest distribution/kernel, architecture, vCPU count, guest RAM, thread settings and dataset/run hashes. Keep the baseline, direct-small, GA-pruned and optional quantised models on the same VM profile for fair comparisons.',
'If full Arm service integration is required': 'Collect training and inference measurements with Python libraries as specified in Section 7.6. Run a light sampled monitor separately from the timed worker; record monitoring overhead. Avoid simultaneous training and inference benchmarks unless measuring that contention deliberately. If a remote GPU is used for training, label its results separately and repeat deployment inference measurements in the native VM.',
'Develop and train natively for speed.': 'Arm64 containers or a generic QEMU Arm guest are deferred, optional compatibility experiments. A native VM result does not establish Arm compatibility. If tested later, report the emulator, architecture and output parity independently; do not convert emulated timing into physical Pi latency, throughput, energy or thermal claims. [S8, S9]',
'Arm64 emulation': 'Optional future Arm64 emulation',
'Tested Arm userspace or guest-OS compatibility': 'Architecture compatibility only if explicitly exercised; not a current release gate',
'Future physical Pi': 'Physical gateway boards outside current scope',
'Actual Pi throughput, latency, memory, thermals': 'No board measurements available; native VM metrics cannot establish board performance',
'Completion requires disjoint evaluation groups': 'Completion requires disjoint evaluation groups, recorded label coverage, repeatable training configuration, compact/masked-model parity, export parity, a frozen threshold and a bundle that runs in the native Linux VM. Include Python-collected training/runtime evidence and VM provenance. Arm compatibility and physical-board testing are not completion requirements. If labels are insufficient, report that blocker rather than substituting CSV rows for temporal samples.',
'Dummy and real export, bundle metadata, reference parity and Arm check': 'Dummy and real export, bundle metadata, reference parity and native Linux VM execution',
'Internal and external detection, resource data, false alerts and benign disruption': 'Internal/external detection, Python-collected VM resource data, false alerts and benign disruption',
'For performance, define the intended lab load': 'For performance, define the VM profile and intended lab load before testing, initially up to 20 virtual clients with one prediction per second and a declared packet rate. Reduce and report the load if the host cannot sustain it. Use Python to record latency, CPU, RSS, queue depth and capture loss. Queues must remain bounded and losses visible. Passing proves the declared VM workload only; no physical-board or Arm64 check is required.',
'Sources were checked on 11 November 2026.': 'Original sources were checked on 11 November 2026. Python measurement references S18 to S22 were checked for this revision on 13 November 2026. Source settings are distinguished from proposed implementation choices. Pin compatible tool versions before building.'
}
for old,new in changes.items():change(old,new)

anchor=find('8 Implementing the Android application integration')
add_before(anchor,'7.6 Python experiment measurement and data collection',True)
paras=[
'Keep two data streams separate. IDS training requires the raw PCAPs and reliable annotations in Section 7.1. Python instrumentation records model/training results; it does not generate trustworthy attack labels. Virtual MQTT/HTTP clients and Scapy fixtures can exercise the pipeline, but synthetic traffic is labeled as laboratory data and does not establish coverage of physical IoT devices.',
'Create a reusable Python measurement module used by training, GA search, export comparison and VM runtime tests. Use time.perf_counter_ns for elapsed times in one clock domain; measure preprocessing, forward inference, service round trip and report commit separately. Use torch.utils.benchmark for eager PyTorch CPU microbenchmarks and time the actual ExecuTorch runner through its Python binding or service boundary for deployed measurements. Use torch.profiler only in separate diagnostic runs because tracing adds overhead. [S18, S19]',
'Use psutil.Process to sample RSS and CPU for the worker and training process, initially every 200 ms. Record child workers separately, the sampling interval and the maximum observed RSS; sampling can miss short peaks. Prime CPU-percent sampling and state whether 100 percent means one CPU core. Summed RSS across processes can count shared pages twice. tracemalloc tracks Python allocations, not complete native tensor/runtime memory. Do not equate it with total model RAM. [S20, S21]',
'Log epoch train/validation loss, learning rate, sample count, epoch duration, examples/second, validation precision/recall/macro-F1 and PR-AUC method; record checkpoint and seed. Log each GA mask, retained channels, fitness, quality metrics, cache status and evaluation time. Compute classification metrics with scikit-learn. Count parameters with PyTorch, calculate tensor bytes explicitly, and measure checkpoint/.pte file bytes with pathlib. MAC/FLOP counts are analytical estimates with a declared convention, not observed hardware throughput. [S22]',
'Store run_manifest.json, epoch_metrics.csv, ga_candidates.parquet, predictions.parquet, resource_samples.csv and benchmark_summary.json under a run ID. Use pandas/PyArrow for tabular outputs and Matplotlib for plots; TensorBoard is optional and never the only record. The manifest includes code/data/model hashes, versions, seed, host/guest architecture, hypervisor, vCPU/RAM allocation, batch/thread settings and monitor configuration.',
'Benchmark in model.eval with gradients disabled. Start with 100 warm-ups and 1,000 timed calls, repeated three times, plus a 30-minute declared-load run. Report cold start separately from warm p50/p95 and throughput; retain raw observations. Compare models under the same VM and background-load settings. Do not infer physical-board power, energy, temperatures or Pi timing from software counters. If CUDA training is later available remotely, synchronise device work for timing and record allocated/reserved CUDA memory separately from CPU RSS.'
]
for v in paras:add_before(anchor,v)

for label,value in [
('S18','Python time.perf_counter_ns. https://docs.python.org/3.11/library/time.html'),
('S19','PyTorch benchmark and profiler. https://docs.pytorch.org/docs/stable/benchmark_utils.html and https://docs.pytorch.org/docs/stable/profiler.html'),
('S20','psutil process metrics. https://psutil.io/api/'),
('S21','Python tracemalloc. https://docs.python.org/3/library/tracemalloc.html'),
('S22','scikit-learn model evaluation. https://scikit-learn.org/stable/modules/model_evaluation.html')]:
 e=E.Element('{'+T+'}p');e.set('{'+T+'}style-name','Standard');e.text='['+label+'] '+value
 find('[S17]').addnext(e) if label=='S18' else find('['+str('S'+str(int(label[1:])-1))+']').addnext(e)

# Retain ZIP members, embedded diagram, hyperlinks and original styles.
target=OUT/'Modular_IoT_Security_Software_Design_VM.odt'
with ZipFile(target,'w') as out:
 for info in z.infolist():
  data=E.tostring(tree,xml_declaration=True,encoding='UTF-8') if info.filename=='content.xml' else z.read(info.filename)
  if info.filename=='meta.xml':
   data=data.replace(b'<meta:keyword>Raspberry</meta:keyword>',b'<meta:keyword>Native Linux VM</meta:keyword>').replace(b'<meta:keyword>Pi</meta:keyword>',b'<meta:keyword>Python measurement</meta:keyword>')
  out.writestr(info,data)
(ROOT/'tmp/cnn_plan/design_vm.txt').write_text('\n'.join(text(e) for e in tree.xpath('//t:p | //t:h',namespaces=NS)),encoding='utf-8')
print('Revised',target)

# Derive the revised plan from the existing authoring source, preserving its layout.
source=(ROOT/'tmp/cnn_plan/build_plan.py').read_text(encoding='utf-8')
def rep(a,b):
 global source
 assert a in source,a[:100]
 source=source.replace(a,b)
rep('Planning version 1.0','Planning version 1.1')
rep('Modular_IoT_Security_Software_Design.odt','Modular_IoT_Security_Software_Design_VM.odt')
rep("ROOT/'Modular_IoT_Security_Software_Design_VM.odt'","OUT/'Modular_IoT_Security_Software_Design_VM.odt'")
rep('version 1 dated 11 November 2026','version 1.1 dated 13 November 2026')
rep('Supplied design version 1, 11 November 2026','Revised design version 1.1, 13 November 2026')
rep('Page 13 defines acceptance; page 14 records handoff files and sources.','Page 13 defines acceptance; page 14 records sources; page 15 specifies Python measurement.')
rep('Confirm design v1;','Confirm design v1.1;')
rep('Arrange Arm64 Linux compatibility access, or permit an explicitly labeled emulated check','Provide the native Linux VM image, guest architecture and pinned runtime')
rep('Arrange Pi 5 8 GB with 64-bit Linux, cooling, storage and power; coordinate gateway lab access','Allocate a native Linux VM and isolated namespaces; coordinate gateway lab access')
rep('Measure actual target latency, sustained load and memory','Measure VM latency, sustained load and memory through Python')
rep('Proposed working envelope: a CPU development machine with 8 GB available RAM can handle fixtures and small trials; 16 GB or more total RAM and SSD storage give more room for extraction. A remote Linux machine with roughly 4 to 8 CPU cores and 16 to 32 GB RAM is a practical batch-processing option. A single CUDA-capable GPU with about 8 to 16 GB VRAM is optional for faster repeated experiments; the data pipeline may remain CPU and disk bound. These are planning estimates, not minimum benchmarked requirements or purchase recommendations.',
'No Raspberry Pi or other board is required. Use a native-architecture Linux VM, initially 4 vCPUs and 8 GB guest RAM if the host has headroom; otherwise start at 2 vCPUs and 4 GB with smaller shards and declared load. Record the actual host/guest configuration. These allocations do not simulate Pi hardware. CPU training is the default; remote GPU training remains optional if the pilot shows a need. Arm64 emulation is deferred, not a completion gate.')
rep('No new device capture is needed for the first public-dataset model if labels pass audit. For an IoT deployment claim, arrange a separate authorized lab capture before final evaluation. Ask the gateway teammate to capture the IoT-facing interface before NAT, with synchronized event logs, device/firmware inventory, attachment mappings and capture/drop statistics.',
'Use public labeled PCAPs for detection experiments and Python-generated workloads in isolated Linux namespaces for software integration. No physical IoT device collection is required. Python logging collects training and model measurements; it does not replace the raw traffic and annotations needed for supervised learning.')
rep('Proposed pilot: at least three representative device types, several independently started sessions on different days, and benign idle, boot, discovery, normal use, video/burst transfer and firmware-update activity. Record device-hours and scenario coverage rather than claiming this sample size establishes generalization. Include separate held-out devices or sessions where possible. Controlled scan/flood evaluation belongs only in the isolated team lab, with known endpoints and onset/stop logs; public attack PCAPs are an alternative for offline evaluation.',
'For the virtual pilot, run separately identified MQTT/HTTP clients and a service namespace through gw. Exercise idle periods, reconnects, normal exchanges and benign bursts; use hand-checked Scapy fixtures for protocol boundaries and authorized isolated attack scenarios for integration. Capture only the IoT-facing virtual interface, with onset/stop, address-mapping and loss logs. Label these simulated workloads rather than physical device observations.')
rep('Label the lab material development or final test before use. Save captures, scenario timeline, clock-offset notes, topology, ground-truth method and exclusions. If lab results inform retraining or threshold changes, reserve new sessions for final testing. Physical collection can be deferred, but the report must then limit its claim to public datasets and tested integration.',
'Predeclare lab sessions as development or final test. Save topology, scenario timelines, capture quality and label provenance. If results guide tuning, reserve fresh sessions for evaluation. Claim public-dataset detection and native VM integration only; physical-board performance and real-device generalization remain untested.')
rep('Arrange Arm64 userspace access or an explicitly labeled emulated environment. Approve any extra compute budget for optional QAT separately.',
'Provide the native Linux VM and runtime details. Optional QAT or remote training requires an agreed compute budget; no board or Arm64 environment is needed.')
rep('Coordinate the gateway teammate and arrange the isolated virtual lab. Supply the physical Pi when actual target performance is to be claimed; arrange fresh IoT captures as described on page 7.',
'Coordinate the gateway teammate and arrange the native Linux VM, isolated virtual topology and workload manifests described on page 7. No physical board is required.')
rep('Pipeline parity, failure-injection evidence and separately labeled native, Arm-emulated and physical-Pi measurements.',
'Pipeline parity, failure-injection evidence and Python-collected measurements tied to the native VM configuration.')
rep('Record cold start, p50/p95, RSS, CPU, queue depth and capture drops under a declared client count and packet rate; start with the proposed 20 clients and one score per second. Test multiple thread counts on development workloads. Run Arm64 compatibility checks, and physical Pi tests when available with OS, cooling and thermal state recorded. Use new lab captures only in their predeclared development or final-test role. Do not present emulator timings as Pi results.',
'Use the Python measurement specification in Section 14 to record cold start, p50/p95, RSS, CPU, queue depth and drops. Start at the proposed 20 virtual clients and one score per second, lowering the declared load if needed. Compare thread counts under the same VM profile. Save host/guest architecture, hypervisor, resources and background-load notes. Use lab captures only in their declared role. Native VM validation completes this phase; Arm/board performance remains untested.')
rep('A release may be a public-dataset and OBSERVE-mode demonstration while physical IoT validation remains pending. State precisely which components and environments were exercised, so the team can use the document and evidence honestly in its technical report.',
'The release is a public-dataset and native Linux VM demonstration, initially in OBSERVE mode. No physical-board or Arm64 test is a release dependency. Report the virtual workloads and Python-collected measurements without claiming real-device or board performance.')
rep("('Compatibility','Exact exported bundle on Arm64 runtime','Native/emulated/physical results labeled independently')", "('VM compatibility','Exact exported bundle in native Linux VM','Record actual architecture and runtime; Arm64 is optional')")
rep('use a sustained 30-minute load run to expose queue growth and thermal effects. State clock, thread count, power mode, OS and concurrent load.',
'use a sustained 30-minute VM load run to expose backlog and contention. Use Python timers and psutil as in Section 14; record clock, threads, guest resources, hypervisor and background load.')
rep('Measure Pi energy and thermals on physical hardware.','No physical-board energy or thermal measurements are required or claimed.')
rep('operational alert objectives and physical Pi availability','operational alert objectives and available VM resources')
rep('CNN_IDS_Implementation_and_Optimization_Plan.docx','CNN_IDS_Implementation_and_Optimization_Plan_VM.docx')

# Update the future prompts to make instrumentation part of the implementation.
rep('Record commands, versions, artifacts, meaningful checks, unresolved issues', 'Use the native Linux VM and Section 14 Python measurement protocol. Record commands, versions, artifacts, meaningful checks, unresolved issues')
rep('Save the compatibility evidence and exact reproduction command.', 'Save the native VM compatibility evidence, environment manifest and reproduction command. Define the shared Python run logger from Section 14.')
rep('Measure CPU pilot cost and estimate remaining compute before large runs.', 'Log epoch loss, metrics, wall time, examples/second and sampled process RSS/CPU with Python. Estimate remaining compute from the CPU pilot.')
rep('Report candidate counts, compute cost and quality/retention trade-offs.', 'Save Python-collected candidate evaluation times, cache hits, fitness and retained-channel counts, plus quality/cost trade-offs.')
rep('Measure exported bytes and runtime cost.', 'Use pathlib for exported file bytes and Python timing around the actual ExecuTorch runner for VM runtime cost.')
rep('runtime measurements, model provenance', 'Python measurement logs, VM provenance, model provenance')

append=r'''
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
'''
source=source.replace("path=OUT/'CNN_IDS_Implementation_and_Optimization_Plan_VM.docx'", append+"\npath=OUT/'CNN_IDS_Implementation_and_Optimization_Plan_VM.docx'")
(ROOT/'tmp/cnn_plan/build_plan_vm.py').write_text(source,encoding='utf-8')
exec(compile(source,str(ROOT/'tmp/cnn_plan/build_plan_vm.py'),'exec'))
