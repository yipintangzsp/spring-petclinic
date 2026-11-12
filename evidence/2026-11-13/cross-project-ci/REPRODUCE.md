# REPRODUCE — W11 cross-project / cross-CI verification (2026-11-13)

## Inventory (read-only)
- Plugin projects: `cat infra/security/manager-v2/*/projects.json` on branch
  `fix/security-manager-plugin-switches` (HEAD moving during the round due to
  parallel lines; no source files were modified by this line).
- GitLab (public API, no credentials): from the Mac,
  `curl http://192.168.1.58:30080/api/v4/projects?per_page=100&simple=true`,
  `.../projects/<id>/pipelines`, `.../projects/6/pipelines/208/jobs`,
  `.../projects/2/pipelines/203/jobs`. Sanitized excerpts in `raw/gitlab-*.json`.
- Cluster state via devops readonly kubeconfig: GitLab pod + gitlab-runner
  deployment Running in ns-devops; no logs/config secrets read (runner host
  config is root-owned 0600 and was not read).

## Driver (real runs)
`evidence/2026-11-13/cross-project-ci/run-driver.mjs`, run on the Mac:
```
export PATH=/opt/homebrew/bin:$PATH
node evidence/2026-11-13/cross-project-ci/run-driver.mjs
```
It uses `realManagedRegistry()` exactly as `view/actions.mjs` does for sbom
(context caps `{SBOM_FILE: AVAILABLE}`, SSH to the Lima VM entry
`security-sbom@192.168.64.11`, CycloneDX Maven plugin pinned by projects.json).
Runtime artifacts land in `.devsecops/cross-project-runs/<runId>/` (untracked
runtime state); sealed artifact copies are under `raw/<tag>/`.
Output summary: `raw/core-driver-summary.json`. Expected tail:
```
CASE project-a-real java-sbom-demo COMPLETED PASS eval=1
CASE project-b-real java-sbom-demo-b COMPLETED PASS eval=1
ROUTER ... DRY_RUN / DELIVERED_LOCAL_ONLY (both projects)
CASE switch-b-disabled java-sbom-demo-b DISABLED null eval=0
CASE switch-a-unaffected java-sbom-demo COMPLETED PASS eval=1
CROSS * SBOM_PROJECT_NOT_AUTHORIZED (x4)
DRIVER_DONE
```

## Regression (no source changes by this line)
```
node --test infra/security/manager-v2/*.test.mjs        # 176/176
node --test infra/security/*.test.mjs infra/observability/*.test.mjs  # 147/147
```

## Second CI
Not executed: creating/triggering a GitLab pipeline requires authenticated
GitLab access (401 on /api/v4/version and /api/v4/runners without a token).
Historical job evidence shows `stuck_pending_no_matching_runners`.
See verification.json `secondCI.gaps` (G-CI1..G-CI4) for exact unblock steps.
No pushes were made anywhere; no Jenkins build was triggered.
