# Bounded Host / Guest sampler — offline candidate

This directory is independent of Security Manager, Jenkins, Kubernetes and Trivy.
No production integration or online scheduler is enabled. `sampler.py` is an
executable one-shot collector; `runner.py` deliberately rejects SSH executables.
Only audited Python workers may run in the offline supervisor. `contract.ssh_argv`
constructs a future reviewed command but never executes it.

## Entrypoints

```sh
# Future NON-PRODUCTION Linux validation, only after selecting an authorized sandbox:
python3 -B sampler.py --role guest --source-id linux-sandbox --pids 123,456
# Native Darwin read-only test: own process only; no QEMU lookup or argv reads:
python3 -B sampler.py --role host --source-id offline-host --pids self
# A clock-only handshake reads no metrics / processes:
python3 -B sampler.py --role host --source-id offline-clock --clock-only
```

Do not run these commands on devops under the current authorization. Reproduce
this round's tests only through a new sandboxed temporary copy and new evidence
attempt name; never invoke old replay / archival entrypoints to overwrite results.

Linux: six fixed system files (`loadavg`, `stat`, three PSI files, `meminfo`), at
most eight preselected PIDs, stat/cgroup reads only, no `/proc` discovery, no
threads traversal, no argv/environ/status dumps. All path components use
O_NOFOLLOW; proc reads are nonblocking and capped at 16KiB. Missing / invalid /
permission-denied metrics or PID reuse fail the sample rather than becoming 0.
PID tick deltas use each read's own monotonic window; Pod UID is extracted without
exporting the cgroup path. No root, Docker socket or Kubernetes credentials.

Darwin: libSystem `host_processor_info(PROCESSOR_CPU_LOAD_INFO)`, read-only
`host_statistics(HOST_VM_INFO)`, selected `sysctlbyname`, libproc
`proc_pid_rusage(RUSAGE_INFO_V2)` / `proc_pidpath`. Mach ports / returned VM arrays
are released. Paths are reduced to QEMU / selected-process category and discarded.
No shell, ps, top, vm_stat, plugins or new software. At most 128 CPUs are accepted.
A fixed PID list is not a global top-process ranking. Correct VM/QEMU PID mapping
must be established separately before a future online capture; stale historical
PIDs may not be reused blindly. Source IDs are operator-provided labels, not
cryptographically attested machine identities.

## Budget and fail-closed behavior

Hard coded in `sampler.py` and `contract.py`:

| Budget | Limit |
|---|---:|
| Selected PIDs per worker | 8 |
| File read | 16KiB |
| Collector stdout | 32KiB |
| Per-worker stderr retained by supervisor | 2KiB, bytes counted only, content discarded |
| Sampling delta sleep | 200ms default, at most 250ms |
| Collector SIGALRM wall deadline | 2.5s, excludes interpreter startup |
| Supervisor worker/transport wall deadline | 4s, includes spawn |
| Worker CPU | 0.25s, process lifetime, including startup; audited post-run |
| Worker maximum RSS | 64MiB, audited with getrusage/wait4 |
| Maximum simultaneously owned local workers | 2 |
| Maximum samples | 6 |
| Minimum sample interval | 120s |
| Session wall deadline | 620s, including readiness/cleanup/final health envelope |
| Session evidence payload | 512KiB |
| Clock uncertainty half-width | 500ms maximum |
| TERM grace / reap deadline | 100ms / 500ms |

These limits are tighter than the old 1 CPU-second per-side and 15/20 wall-second
rules; no old limit is relaxed. CPU/RSS are **accounting-based stop rules, not
cgroup CPU/memory quotas**. Bounded input and output avoid uncontrolled allocation;
any measured overrun makes the session fail and forbids another sample. Supervisor
CPU is independently reported; it is not mixed with worker CPU and is not inferred
from elapsed time. No production RSS or CPU-overhead acceptance has occurred.

Guest cheap precheck stops BEFORE PID reads when load1 >=8/vCPU, CPU PSI some
avg10>=70%, memory some avg10>=20%, or I/O full avg10>=30%; repeated after the
window. Host stops for load1>=2/CPU or free+inactive<512MiB. Raw macOS memory pressure
enum is preserved, not interpreted as Guest PSI or proof of memory availability.
Free+inactive is a conservative test admission heuristic, not guaranteed allocatable
memory. This round used no artificial CPU/memory load. There is no automatic retry.

Collector exits: 0 OK; 2 argparse rejection; 20 invalid/missing/error facts; 21 task
timeout; 22 self CPU/RSS budget; 23 output cap; 24 disconnected output; 30 pressure
stop. Parent rejects malformed output, error status even with exit0, nonzero exit,
timeout, excess output, or resource overrun, then stops/reaps the peer. It only
terminates its exact owned PIDs; no global kill. Audited collectors never fork.
This is NOT a general untrusted process-tree isolation or remote SSH cleanup proof.

## Time protocol

Every collector records nanosecond UTC wall values, ISO UTC milliseconds, UTC
zone offset=0, local timezone offset, and local monotonic start/end. CPU/process
intervals use local monotonic only. Different machines' monotonic values are NEVER
subtracted from one another. OS clock-sync state remains UNKNOWN without separate
read-only evidence. Timer resolution is not clock accuracy.

For Host send H0, Guest receive G1, Guest send G2, Host receive H3, estimate
Guest-minus-Host UTC offset in `[G2-H3, G1-H0]`. Midpoint is an estimate only;
half-width is uncertainty. No symmetric delay assumption. SSH startup is included
in the uncertainty rather than subtracted or guessed. Require ordered intervals,
local UTC-vs-monotonic duration discrepancy <=20ms on each machine, and uncertainty
<=500ms; otherwise fail and stop. An unobserved wall-clock step/drift inside the
exchange remains a limitation; this is not NTP/PTP verification.

Map Guest event window to Host as `[Gstart-offsetUpper, Gend-offsetLower]`.
Only uncertainty-expanded overlap is a correlation candidate, never causal proof.
Each subsequent sample needs its own bounded exchange; don't extrapolate an initial
offset for ten minutes assuming unmeasured drift. Current tests include a true
local-process handshake and injected clock offsets/steps; real Host/Guest clocks
were NOT tested.

## Future execution contract (not enabled)

Preflight (fresh evidence boundary, source hash, fixed source/PID identities,
non-root access, room for output) → independent readiness (no healthy result
inferred from old data) → clock-only exchange → bounded sampling → independent
per-side receipts → uncertain-window join → correlation analysis → reap/cleanup
→ separate final health snapshot.

`Session` rejects count/cadence/deadline/total-output violations and closes after
any failed sample. Tests use a virtual scheduling clock for 120s cadence tests;
the real executable performance series is a short OFFLINE series, not a ten-minute
production observation. Clock/readiness/health steps must consume the same 620s
outer deadline. No timeout may trigger retries or start another worker.

The production transport/driver is intentionally not implemented in this phase.
A future strict SSH transport must verify existing trusted host keys, use one
connection attempt, no sudo, no agent/port forwarding/proxy/local command/control
master/persistence, a fixed collector hash, bounded stdin/out, and a Guest-side
independent timeout. Remote SSH/session cleanup, Linux-native permission/overhead
and clock-sync state must be verified in an authorized non-production Linux context
before any production launch. Do not equate locally reaped Python children with
proof that a disconnected remote process was reaped.

Normal baseline evidence establishes cost/range only. Incident evidence additionally
needs existing Node/Pod Ready/restarts/Traefik5xx time series and fresh runnable/PSI/
selected PID/Host/QEMU counters. Kubernetes and historical Prometheus reads are a
separate bounded stage, never a loop in the collector. If production is already
severely unavailable, stop extra sampling rather than chase a complete report.
No active fault injection. No automatic production modifications.
