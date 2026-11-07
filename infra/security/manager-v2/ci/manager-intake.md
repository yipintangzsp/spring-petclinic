# Security Manager CI intake v1 — controlled nonproduction acceptance

This adapter reuses the existing Manager intake, fixed Linux Gitleaks runner, Policy owner, sealed Artifact validation, Result Router and Loki Consumer. It does not replace the earlier restricted-Agent Candidate contract or activate production Security Manager.

## Actual execution

On 2026-11-07, one project-12 documentation Push to `security-demo/gitlab-push-20261105` created Commit `d7faa2a512ff00b88ac3a3848fa71292b3095819` and GitLab Hook 5 event 342. Jenkins #7 failed before Manager invocation because Groovy expanded a newline inside the Node heredoc. No scanner or Policy ran. The user explicitly approved one resend of that exact event; GitLab created event 343 and automatically started `security-gitlab-push-demo #8`, SUCCESS.

Manager Run `web-bfcb08f9-e841-4972-8ecc-858355719a83`: project `python-fixture`, REAL / COMPLETED, Gitleaks exit 0, 0 findings, Policy PASS, evaluationCount 1. Result Digest `6d099ffe64f725d9454408e82c3e2526ea73a2f755c6f83ad9bdd75de3f72dd1` is shared with the Jenkins archive, existing Manager record, Loki query and Grafana query. Existing Grafana non-admin queries returned the run on five panels; no Dashboard changed. Evidence: `evidence/2026-11-07/ci-standard-real/acceptance.json`, `grafana-query.json`, `cleanup.json`, `production-health.json`.

The GitLab Commit is **trigger provenance**. Actual scanning covers the approved fixed Clean fixture, not the GitLab checkout. This distinction is explicit in `ciContext.sourceScope` and the UI.

## Contract / authorization

CI intake is mounted only on a temporary owner-private UNIX socket by the existing Manager process when `.devsecops/security-view-ci-capability-v1.json` exists and is unexpired. No LAN listener or general browser proxy is created. `POST /v1/runs` accepts exactly:

- projectId, sourceRepository, commitSha
- ciProvider, jobId, buildId, trigger
- pluginId, scenarioId

Only code-owned `ci/projects.json` scope and the precise prebound Commit/Build are accepted. No shell, filesystem path, scanner option, URL override or caller Policy configuration is accepted. Global/project/plugin controls come from the current Manager resolver before admission. A disabled request starts no scanner, evaluates no Policy and consumes no run budget. An exclusive private claim limits the capability to one admitted run. `GET /v1/runs/<runId>` exposes only that capability's claimed run and a bounded standard projection. Wrong identities/projects/plugins, other run reads and browser routes are rejected. Anonymous and SBOM project credentials cannot read CI records from the browser API; only the local operator can.

The fixed `manager-ci-v1` SSH wrapper retains existing scanner/proof behavior for all old commands. The Jenkins key remains `restrict` with forced command, no PTY/shell/forwarding. Its credential ID is not proof of Job isolation. The server principal may invoke only the fixed project/plugin, even if a caller spoofs Job strings. For this acceptance, real GitLab event data and Jenkins Cause independently established the Commit/Build correspondence.

The temporary reverse stream-local SSH bridge exposes only the CI UNIX intake. Linux socket directory UID1000/GID24021 mode0710 and socket0660 were verified; an unrelated UID was denied. The scoped CI token stayed root-owned0440/GID24021 on Linux and owner-only0600 on Mac; it never entered Jenkins, logs, source, page or Artifacts. No sshd, Docker or Kubernetes permission changed.

## Lifecycle and rollback

The approved one-run capability, Git write token, new wrapper, socket directory and exact temporary SSH process were removed after #8. The original scanner authorized_keys bytes and original demo Job definition were restored; #7 FAILURE and #8 SUCCESS and archives remain. Production Job/V1 Summary/Deployment/Argo hashes stayed unchanged. The existing Manager restarted with no CI socket and still serves the immutable result.

A new run needs a fresh explicitly scoped approval/capability, exact expected Commit/Build and bounded temporary bridge. Do not recreate a permanent service or reuse the revoked credentials. `manager-demo.Pipeline.groovy` is a parameterized reviewed template, not an enabled general-purpose job. Do not import the legacy ci/README.md Agent candidate as part of this path.

The existing UI is http://security.devops.local:17862/#live-validation . Use the existing local `node infra/security/manager-v2/view/control.mjs open` if operator login is needed. It displays Project, repository, Commit, provider, Job/Build link, trigger, exact scan scope, Run ID, Policy, Result Digest and Loki/Grafana link. Current browser control was disabled in Work settings; HTTP/data/served UI code were verified, and browser observation is NOT_TESTED.

Only eight relevant CI contract tests and bounded real authorization negatives were run. No repeat Gitleaks/SBOM/Jenkins/production regression was performed. Existing SBOM A/B artifacts remain unchanged. Old Harbor candidate SBOM remains UNVERIFIED, signature MISSING; no production release/rollout occurred.
