# Mac Gitleaks admission correction — actual memory pressure blocker

Baseline f346fdae. Gitleaks-only budget correction; no other scanner, Linux runner, production Gate, Policy Engine, or V1 behavior changed.

Old view/actions.mjs:52 measured Mac Host, never Linux Guest. It used current (not cached) os.freemem and load1/(CPU count); disk was correct bavail*bsize, not total capacity. No Trivy floor or VM RAM reservation was used. Units were correct, but free physical pages do not measure Mac reclaimable memory, and load average is not CPU utilization. These measurement errors are corrected only for Gitleaks.

New mac-budget.mjs uses a fresh 250ms host CPU-tick interval, vm_stat free+file-backed reclaimable bytes, filesystem bavail*bsize, and actual kernel pressure. 512MiB memory/disk minima and 75% CPU busy ceiling are retained numerically. The explicit NORMAL pressure prerequisite prevents file-cache or memory_pressure percentage from concealing actual system pressure. Unknown/out-of-range telemetry fails closed. Elevated pressure rejects before scanner launch. This does not assert a hard allocation/RSS limit or Linux-equivalent process isolation.

Apple source for the native enum (not dispatch bit flags): https://github.com/apple-oss-distributions/xnu/blob/main/doc/vm/memorystatus_notify.md . The native enum uses Normal0, Warning1, Urgent2, Critical3, Jetsam4; Urgent is synonymous with Warning. Initial commentary called2 Warning; persisted evidence uses the more exact URGENT name.

## Actual host observation and API request

At 2026-11-05T07:42:27.132Z: CPU busy 55.51% despite load1 10.63; reclaimable estimate 5212209152 bytes, free physical pages 62390272 bytes; available disk 16585613312 bytes; memory pressure2/URGENT. Swap observation: vm.swapusage: total = 4096.00M  used = 2592.81M  free = 1503.19M  (encrypted). Repeated kernel queries remained2. QEMU observation is in host-resources.json: about8GB RSS and multi-core CPU consumption, recorded as current load, not blamed for any historical incident.

Gitleaks small-fixture budget retains512MiB admission headroom. Prior Linux runner used GOMAXPROCS1, GOMEMLIMIT128MiB (soft Go heap target, not hard RSS cap), timeout10s. Actual Mac peak demand remains NOT_TESTED; no invented measurement or performance guarantee.

POST http://security.devops.local:17862/api/run with exact Origin/Host and CSRF for Gitleaks+Clean was actually sent, returning new Run ID web-a29931ae-006b-48cc-a57c-b44f0dd106d6. The actual outcome is BLOCKED / MAC_MEMORY_PRESSURE_BLOCKED, policy=null, evaluationCount0, scannerExecuted=false. No Gitleaks process, exit code, raw report, fact digest or Result Digest exists. Audit UUID/digest are not scanner results. No later Finding/Semgrep/Cosign expansion.

## Tool inventory and trust

Previously inventoried local binaries/caches have no trusted Darwin executable. Historical8.30.1 success used pinned Linux/arm64 image/binary; no Mac equivalence claimed. Official API metadata for8.30.1 obtained with macOS system curl TLS verification, showing Darwin ARM64 archive and checksum asset. Python TLS request initially failed due its local CA store; no verification was bypassed. Only public metadata was fetched, no binary installed/executed. Official checksum/archive can be verified into a project-private path after resource admission is safe. Global tools untouched. Manager/runner/Policy extraction is not begun while the current host remains at elevated pressure; neither a new adapter nor Real execution is claimed.

## Tests and scope

Five targeted budget tests passed (page units, native pressure enum, elevated pressure rejection, retained minima, invalid telemetry fail-closed). No hundreds of unrelated tests, no new scan reports. No timeout/cleanup scanner test is claimed because no scanner process started. Existing Host/Origin/CSRF, single-flight/body cap/persistence code unchanged. Browser click NOT_TESTED.

Minimal next step: reduce non-production Mac application memory demand without stopping/reconfiguring K3s VM, confirm current kernel pressure NORMAL0, then continue verified private tool installation and minimal Mac runner adaptation. Do not lower pressure requirement or count any historical result as REAL.

Rollback: restore only mac-budget files and the Gitleaks budget branch to f346fdae; prior budget may misclassify Mac cache/load. The safer operational disable is control.mjs stop. Keep audit evidence. No production rollback required. No push/release/rollout.

Production read-only snapshot: HEALTHY; nodesReady=True; PetClinic ready=3; HTTP=200; Argo=Synced/Healthy; socket=0660; Jenkins#270=SUCCESS; V1 unchanged=True; spec/image/Trivy metadata/Docker daemon unchanged={'specSha256': True, 'image': True, 'trivyDbMetadata': True, 'dockerDaemon': True}. No production writes.
