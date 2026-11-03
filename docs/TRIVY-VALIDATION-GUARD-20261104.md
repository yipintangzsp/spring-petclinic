# Trivy validation-only guard — Phase 1

The production entry point, formula, metadata checks, vulnerability classifier, Gate and callers are unchanged. No production feature flag was activated. `scanner-db-refresh.mjs` remains byte-identical.

`scanner-validation-guard.mjs` provides an additional explicit facade:

- Default / `mode: production`: delegates to unchanged production IO. Ambient `TRIVY_GUARD_MODE` cannot select validation mode. Validation configuration in production is rejected.
- `mode: validation-only`: explicit isolated workspace, verified binary, owner assertion, manifest provider and reviewed budget. No production cache, credential, proxy or Kubernetes configuration fallback.
- Existing callers still use original `scannerRefreshIO()`. No production or runtime pipeline is activated.

Production refresh requirement remains `capacity × 0.15 + 12 GiB`.

The non-adjustable validation hard floor is the existing release-preflight stop line, `ceil(capacity × 0.15 + 8 GiB)`. It is deliberately conservative, not a relaxation of production limits. The additional validation budget can exceed the production refresh requirement.

## Admission proof

Before workspace creation or updater launch, every guest/cache/temp/overlay and physical backing storage domain needs:

```text
available >= hard floor
           + proven maximum additional allocation (refresh AND scan/report)
           + instantaneous writes during detection/termination
           + failure-cleanup allowance
           + bounded other writers
```

Require both DB artifact digests, hash-bound reviewed evidence identity, complete old/new DB/download/extraction/temp/scan coverage, cleanup proof, physical allocation proof, inode budget, fresh measurements, no DiskPressure, confirmed owner and writer isolation. A sampled maximum or OCI compressed layer size cannot bound extraction, old/new overlap, Java DB, scan output or host COW allocation.

The proof loader checks bytes against a reviewer-provided SHA256. It does not mathematically prove a bound or approve a self-authored PROVEN claim. Phase 2 still requires evidence review. No real approved proof file is supplied. Synthetic budgets exist only in labeled tests.

## Monitor and cleanup

Fixed settings: interval 100ms; maximum gap 1000ms; sample timeout 500ms; SIGTERM grace 1000ms; SIGKILL grace 1000ms; maximum duration 210s; in-memory log limit 1MiB. The instantaneous-write bound must cover at least the complete configured 3600ms detection/termination window. If it cannot be established, do not start.

Read actual statfs available allocation and inodes, not apparent size or advertised PVC capacity. VM backing storage needs its own observer and budget. Missing domains are refused. Monitor owner, pressure, device identity, remaining safety space, write bound, sample continuity and final state. Monitor failure, cancellation, timeout, log overflow or unsafe measurements terminate only this invocation's detached process group. Successful process exit with unknown final storage state is not success.

Random owner marker and root inode/device protect the newly created private workspace. Only its cache/temp paths are cleaned. No production cache deletion, generic pkill, production Secret access or global environment modification. Active/unproven stopped processes, foreign/symlinked markers and replaced roots block deletion. Preserve uncertain state and STOP. Generic process tests use disposable Node children; they are not Trivy execution evidence.

`createValidationRefreshIO` consumes existing official-manifest verification and existing Trivy download flags with its own cache. Binary SHA and per-kind reviewed artifact identity are checked before download. Its manifest provider is explicit and must use separately reviewed read-only transport without production proxy inheritance. No production Jenkins pipeline calls this adapter.

## Stage boundaries

1. Implement/test/record Phase 1 first.
2. Only proven real storage and all conservative bounds permit a same-run DB refresh and native scan. Insufficient space or unknown peak means INCOMPLETE and STOP; never repeatedly lower thresholds.
3. Only native reports, unchanged old Gate vs Policy decisions, single Policy evaluation and resultDigest reuse permit same-run DefectDojo validation. Never combine historical runs into 16/16.

The frozen Trivy compatibility manifest pins the pre-Helm Jenkinsfile.security-audit SHA. Previously authorized additive Helm blocks changed its raw SHA. Strict current-tree replay returns POLICY_ERROR: frozen Trivy source changed. Do not rewrite historical manifests, strip source for a falsely labeled current-tree success or bypass the check. Record a separate runtime/Policy integration blocker and resolve it through a reviewed versioned compatibility transition later.

No Summary V2/Security Manager activation, Argo/GitOps mutation, image promotion, release or rollout.
