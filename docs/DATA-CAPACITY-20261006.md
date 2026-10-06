# PostgreSQL data and capacity phase — HPA gated by worker protection

## Actual progress

The data phase is deployed. CPU HPA and its joint maintenance exercise are **not yet deployed or passed**. A real aliyun NotReady event occurred during a rollout with old/new JVM overlap, and load was stopped. The node subsequently recovered. Immediately after the incident, application replicas recovered to three on devops (one) and ucloud (two). The subsequent zero-surge compression release restored one Ready Pod on each of the three nodes. This is a successful application release, not completion of the HPA phase.

Evidence directory: [data-capacity](../evidence/2026-10-06/data-capacity/). Times in raw evidence are UTC; the incident occurred around 03:27 China time on October 6. The resumed session found all nodes Ready after the node's services restarted around 08:08; no physical reboot or node restart was initiated by this task.

## Required 24-item result ledger

| # | Result | Actual finding |
|---|---|---|
| 1 | PostgreSQL deployment | ns-data/postgresql, single Deployment, Recreate, PostgreSQL 18.4 arm64. All application Pods use petclinic/public on the same Service. |
| 2 | PVC/PV | postgresql-data, 2Gi RWO local-path, PV pvc-4da56878-b3e9-4588-b6a4-21c90821002f; local path and node affinity devops; reclaim Delete. Data directory /var/lib/postgresql/18/docker is under the PVC mount. The 2Gi claim is not a demonstrated filesystem quota. |
| 3 | Pod recreation persistence | Not performed. A live Trino catalog references this server, albeit nonexistent database devops, and registry contains dcp_persistence_test. No active non-PetClinic clients were observed, but absence of current connections does not prove absence of shared dependency. Private pg_dump -Fc was saved mode 0600 and pg_restore -l succeeded; neither proves actual restore or recreation persistence. |
| 4 | Tables | owners/pets/vets/visits base counts 11/13/6/5. All have identity PKs. pets has type/owner FKs; visits has pet FK; vet_specialties has two FKs and a unique pair. Existing FK/index definitions are in database-before.json. Owner and visit FKs are nullable in the existing schema; audit found zero orphan pets/visits. |
| 5 | Demo scale | 200/350/20/1200 total. Two seed executions returned identical counts; base row fingerprints and owner #1 hash unchanged. IDs 1000001+ distinguish demo. Explicit demo_enabled flag, advisory transaction lock, reserved-ID collision rejection and version marker; never application bootstrap. |
| 6 | SQL/index | Demo owner contains search uses a small sequential scan: 0.161ms; owner-pet indexed query 0.032ms; pet-visit indexed query 0.092ms. No index added. EAGER owner/pet/visit mappings retain potential bounded N+1 behavior; pg_stat_statements is absent and per-request SQL counts were not instrumented, so this audit does not claim absence of N+1. Pagination bounds result pages; measured queries showed no material regression requiring refactoring. |
| 7 | Hikari | Before: idle10 x3, active0, pending0. During mixed startup/load samples active max4, pending max0. Production now max6/minIdle2 per Pod; up to36 pooled connections at six replicas, leaving room below max_connections100. No forced connection termination or global DB logging change. |
| 8 | Node baseline | Initial 12 continuous stable samples: devops CPU avg1.342 cores/max1.963, memory avg15728Mi/max15853; aliyun avg0.092/max0.130 cores, memory1078/max1087Mi with one app; ucloud avg0.061/max0.154 cores, memory2369/max2373Mi with one app. Raw node requests/limits/allocatable/pressure and later incident/startup samples are retained. Resumed idle samples must be treated separately because aliyun no longer hosts an app. |
| 9 | N-1 | Conservative initial plan reserves 2048/256/512Mi on devops/aliyun/ucloud, budgets640Mi per app; safe app slots3/0/2 versus request-only18/3/5. With devops unschedulable only2 conservative safe slots remain, so even3 is not guaranteed under this envelope. With aliyun unavailable,3–5 fit the envelope,6 does not; with ucloud unavailable,3 fits,4–6 do not. These are calculations, not physical-node outage tests, and not proof of scheduler refusal. |
| 10 | requests/limits | Memory request256→512Mi because observed stable working set364–406Mi exceeded its prior request. Mixed startup/load sampled maximum working set437.15Mi, RSS432.12Mi, heap119.53Mi. CPU request100m and limit500m, memory limit768Mi unchanged. Startup CPU peak462m; high startup throttled-period ratio (~1) is distinguished from steady load, not reported as the fraction of CPU time lost. No CPU increase was made while worker health was uncertain. |
| 11 | PDB/HPA design | Live PDB remains minAvailable2, with fixed3 application replicas. Option A min3/PDBmin2 preserves one voluntary disruption; option B min2/maxUnavailable1 permits only one remaining Ready Pod during maintenance. A provisional capacity-limited C is min3/max4/PDBmin2, pending worker protection and capacity recalculation. No HPA installed. |
| 12 | CPU target | Proposal70% of100m (70m/Pod). Stable idle is a few mCPU; 5 QPS mixed traffic approached roughly55–125m depending Pod and startup. 70% separates idle noise from sustained work while retaining500m burst limit. Needs a clean post-fix load baseline; not claimed finalized. Proposed up window45s +1 Pod/90s, down window300s −1 Pod/120s. |
| 13 | HPA expansion | Not tested; replicas created during rollout are not HPA scaling. |
| 14 | Maximum successful replicas | Three desired and Ready; transient rollout extra Pods must not be called an HPA maximum. |
| 15 | HPA scale-down | Not tested. Existing graceful shutdown remained configured; migrated/replaced app Pods returned to three. |
| 16 | HPA + maintenance | Not started because no validated HPA and worker memory protection is missing. The unexpected worker incident is separately recorded, not substituted for the requested controlled joint exercise. |
| 17 | Pending | No sampled FailedScheduling/Pending capacity fault was used as proof. The affected new aliyun Pod was Running/unready and later Terminating; this differs from Pending. |
| 18 | Real blocker | Aliyun kubelet stopped heartbeats; liveness/startup failed, SSH and kubelet TLS initially timed out. Prometheus showed full memory stall up to67%, iowait up to92%, OOM counter0. Current kubelet config has no reserve and no memory eviction threshold, despite almost the entire node memory being allocatable. Exact kernel/process cause still needs corroboration. |
| 19 | HTTP | Completed light stage45/45 and moderate300/300 returned200, p95 1.266s and1.249s respectively. These stages overlapped a rollout. The20-QPS stage was manually interrupted and its full HTTP results were not saved; no zero-failure claim is made for that unfinished stage. Business audit paths after recovery returned200; admin endpoints remained404. Sampled Ready Endpoint minimum2. |
| 20 | PostgreSQL pressure | No sampled Hikari pending; active max4; no orphan or base data changes. Slow logging off and no pg_stat_statements, so absence of sampled pool waits does not establish absence of every short-lived DB stall. Old JDBC connections from unreachable Pods remained temporarily until node recovery; final evidence distinguishes these from steady pools. |
| 21 | HA boundary | [HA Boundary](HA-BOUNDARY.md): Pod HA complete; application node HA demonstrated for prior maintenance but current capacity constrained; ingress partial; DB/control-plane/storage HA not complete. A devops physical outage loses shared dependencies even if workers can host app Pods. |
| 22 | Highest next target | Finish worker protection and the current capacity/HPA phase first. Do not start a different major HA project during this blocker. Subsequent phase ranking below. |
| 23 | Git commits | 8d3d2549 opt-in seed/audit; 3a8f5ef4 disable startup SQL, pool budget, request512Mi and sampler/load/browser tools; a1f2b5b9 zero-surge rollout, Hikari dashboard and HA boundary; final evidence/proposal documentation commit recorded in Git log. Application image remains immutable0.9.0-ci-101; no application source/image change requiring a build. Python scripts compile; manifests passed server-side dry-run; real seed/browser/release/dashboard checks ran. |
| 24 | Argo | Data/config commits reached Synced; after migration the Deployment is3/3 Ready/available. Final Argo revision/health is recorded in resumed-audit/final audit rather than inferred from Git push. The compression rollout records three-node placement,3/3 Ready and Synced/Healthy. Final revision is verified separately after documentation publication. |

## Business verification details

Browser evidence includes home, owner search/city filter/two pagination pages, demo owner and pet details, pet list, vets and status. A synthetic acceptance owner and pet were created and edited; a visit was booked and verified. Only those exact acceptance records were deleted in a guarded transaction; final demo totals stayed200/350/20/1200 and base fingerprints stayed identical. The application has no business DELETE route: SQL cleanup is not presented as a UI deletion feature. Browser test retries handled Spring's `;jsessionid=` redirect; they did not indicate a failed insert/update. Page timings include assets, browser network-idle waiting and cold first access, whereas SQL times are database execution times.

## Incident handling and remaining gate

Load was stopped. The new unready aliyun application Pod was evicted via UID-guarded normal policy/v1 Eviction, first server dry-run then real201 responses. PDB sampled allowedDisruptions0→1, and Ready Endpoints stayed at least2. No force deletion, PDB bypass, full-node drain, PVC deletion, reboot or host-network modification was used. The unreachable Pod objects remained Terminating until the node resumed, and replacements reached Ready on the remaining nodes.

Rollout strategy now maxSurge0/maxUnavailable1 prevents old/new JVM overlap. It intentionally trades temporary3→2 availability for a resource-safe rollout; rollout controllers are not governed by PDB. HPA can still schedule multiple JVMs onto a worker without an accurate allocatable budget, so merely changing rollout strategy is insufficient.

Read the [worker change proposal](ALIYUN-MEMORY-CHANGE-PROPOSAL.md). It is not installed. The user explicitly requires analysis/confirmation before node-wide settings affecting other workloads; approval is pending. Proposed HPA YAML is outside Argo's production source and not active.

Before enabling HPA, adjust only approved scope, repeat stable all-node metrics samples, perform updated N-1 calculations, and resolve replica ownership: add app-specific Argo ignoreDifferences for apps/Deployment petclinic `/spec/replicas` with RespectIgnoreDifferences=true. Otherwise selfHeal can reset HPA changes. Preserve explicit3 in bootstrap or document HPA ownership carefully; verify Argo does not reset four live replicas. Since Argo prune=false, rolling back HPA also requires a reviewed explicit HPA deletion and restoring Deployment replica ownership, not merely deleting its YAML from Git.

## Later major phase ranking — do not start automatically

| Rank | Scope | Career value | Difficulty/resources/risk |
|---|---|---|---|
| 1 | PostgreSQL backup + actual restore/persistence rehearsal, then HA feasibility | High: current data/control storage SPOF | Moderate for isolated restore, high for replication/failover; needs separate storage and worker capacity. Resolve shared Trino dependency first. |
| 2 | GitOps automatic rollback | High: release failure detection/recovery | Medium; modest resources, must distinguish bad release from shared infrastructure failure to avoid rollback loops. |
| 3 | Ingress HA | High: real client entry redundancy | Medium; needs another reachable entry and checked networking. Do not change host networking without review. |
| 4 | MySQL replication/backup/restore lab | High database operations evidence | Medium, existing separate instances available; protect data and keep separate from PetClinic PostgreSQL. |
| 5 | Storage HA | High | High resource/capacity and migration risk; local-path cannot become replicated by changing a label. |
| 6 | Control Plane HA | High | High resources and cluster-wide migration risk; several server nodes and a recovery plan required. |

## Resumed platform impact and scrape qualification

The before/resumed inventory has the same63 non-PetClinic Pod names. Four aliyun DaemonSets increased restart counts by one (Alloy includes two containers); all are now Ready. Consequently this phase does not claim other components were unaffected. PostgreSQL, MySQL, Harbor, Jenkins and other matching platform Pods retained restart counts. The5-hour interval includes external recovery activity; task actions did not restart those services.

The resumed audit found one ucloud application Prometheus target down from a10s scrape timeout despite3/3 Ready. Direct metrics GETs returned200 in8.63s and8.29s versus0.02s on devops. This is another HPA/observability acceptance blocker under diagnosis; successful dashboard responses do not prove every target is stable.

Aliyun's Boot ID changed between the initial and resumed audit; devops/ucloud Boot IDs did not. This confirms a node reboot occurred outside the task's recorded commands; its initiator/cause is unknown. Do not describe it as an automated recovery performed by this task.

Metrics diagnosis found Pod-local generation0.283s versus6.64s cross-node, with247KB transferred and no Content-Encoding. Git4baaf928 enables gzip only for text/plain/application/openmetrics-text; scrapeTimeout stays10s. Compression is a transport improvement, not a claimed fix for memory reservation or the underlying worker network. Its actual rollout/encoding/target results are recorded in separate evidence.

## Compression release acceptance

Git4baaf928 restored3/3 Ready on devops/aliyun/ucloud, with27 rollout HTTP probes all200 and minimum available2. Actual gzip responses transferred6092–7232 bytes versus58076–84408 decoded bytes for the new Pods, including correct200/350/20/1200 business gauges. The new counters/histograms differ from long-running old Pods, so this is not presented as an equal-size before/after benchmark. ucloud direct compressed response0.563s; subsequent Prometheus scrape durations0.679–2.946s, all three targets UP in the last three samples. Long-term network stability and behavior under load are still unproven. Loki returned logs for each new Pod; Grafana datasource checks for Pod readiness and Hikari passed. PostgreSQL counts/base fingerprints remain checked after this rollout.

Continuous evidence is stored in deterministic `.jsonl.gz` archives with uncompressed SHA256 and record counts in sample-archives.json; no database dump or raw node syslog is committed. The earlier NotReady incident and four collector restart-count increases remain part of the evidence. The HPA/node-budget YAML files under `infra/observability/proposed` are outside Argo's source and not installed.

The compression/startup sample maximum working set is 471.79Mi, leaving a smaller margin under the current512Mi request. The HPA preflight should reassess640Mi (about35% over the measured473Mi peak), not lower requests to fit. With the proposed aliyun allocatable~691Mi and Alloy50Mi,640Mi leaves very little scheduler request headroom; verify actual live allocations before declaring fit.

A connection-lifecycle audit also found4 idle ClientRead backends from retired ucloud Pod IPs, alongside6 live idle pool connections. Those clients are not current container metrics targets. They are retained as evidence, not silently terminated. Default TCP keepalive settings are0 (platform defaults); precise disconnect/expiry cause has not been proven. This is not high DB pressure, but pool size alone does not account for stale server sessions. Track this explicitly during the future scale-down test.
