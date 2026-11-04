# Trivy / Helm source-identity transition and execution review

This is a local source-compatibility change. No production pipeline, scan, DB refresh, Argo/GitOps update, image promotion or Summary V2 activation.

## Version lineage

- FROZEN_BASELINE_V1: existing `trivy-parent-baseline-v1.json`, SHA256 `dc3b95d577707b9d9137663bd88a8034f5ce75f87a377a3504c83afd941a6f8f`. Bytes unchanged.
- Original Jenkinsfile identity: `e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2`, reproducible from Git commit 741ea28.
- HELM_SHADOW_INTEGRATION_BASELINE: new `trivy-parent-helm-shadow-v1.json`, SHA256 `e1ac4a6cac7d7282899ece510a411988576a67e272de46f159ddab48ff858ff8`.
- New Jenkinsfile identity: `6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c`. Four additive, pinned Helm shadow blocks introduced in 90b4fca; c2338e0 tightens a Helm input guard, not this Jenkinsfile. 4de943b follows c2338e0 and adds the inactive Trivy validation guard.
- Policy rules remain `baseline-v1`. Source compatibility baseline has its own ID; this is not a change to severity, Gate decisions or report schema.

The source verifier pins both entire manifest byte streams, all thirteen Gate-source hashes, all thirty-three accepted Helm source hashes and explicit parent lineage. Only the two known Jenkinsfile identities are recognized. Unknown edits, changed manifests, unsafe paths, symlinks or missing sources fail closed. No environment variable disables verification.

After authenticating the entire new source, removing exactly one of each reviewed Helm block proves that the original pipeline text is preserved. This is a transition proof only. The actual new Jenkinsfile remains complete during replay; it is not stripped or substituted to get a success.

Only the initial source-lock selection in `trivy-parent.mjs` changes. Its decision body from `const absent` onward is byte-identical to the archived original adapter. The classifier, original scanner/DB helper, manager, commands, report parsing and Policy Engine are unchanged. Identity receipts are separate; no metadata is injected into the active Summary.

## Independent verification

Unmodified existing suites run in disposable copied source trees because their after-hooks write historical-looking output paths relative to cwd. No suite is run against the real historical evidence directory.

1. Original adapter + original matching Jenkinsfile: 190/190 tests.
2. Original adapter + current Jenkinsfile: reproduced 2/190 passing, 188 SOURCE_IDENTITY_LOCK_MISMATCH failures before decisions.
3. Versioned adapter + complete current Jenkinsfile: 190/190 tests.
4. Compare every generated differential record, input/raw digest, old Gate decision and standard decision. All 184 samples and all three aggregate JSON byte streams are identical between original and new versions. There are also six invariant tests. No real scanner is used.
5. Independent source-lock tests exercise known-old/known-new selection, every locked Gate and Helm source mutation, both manifest mutations, missing/symlinked sources, decision-body preservation and marker ambiguity.

### Historical evidence anomaly

At this round's start three old aggregate JSON files no longer match their original artifact manifest. The preceding direct test run's after-hooks had rewritten them. This is a historical evidence-integrity failure, distinct from Gate semantic drift.

Original-v1 replay regenerated exact copies matching each original sealed SHA. They are stored only in this round's directory, with a recovery mapping. Old files and old manifests are not silently restored or rewritten. The original source manifest and original-code reproducibility are verified; the original on-disk evidence bundle still has three failed entries and must be reported as such. Successful new compatibility testing does not erase that anomaly.

## Local rollback

Perform only as a separate reviewed local source change, never a production action here:

1. Copy `versions/trivy-parent.frozen-v1.mjs` back to `infra/security/policy/trivy-parent.mjs`. The frozen copy must hash to `b0b6b034228e26ec8c9b4d052202505999ac9e5534f8106713e55eb6a4f167c6`. Do not import it in place from the versions directory; its relative imports are for the original location.
2. Restore the matching original Jenkinsfile from the pinned V1 text/Git object in the isolated checkout. The restored SHA must be the original identity above.
3. Re-run the original 190 cases in a disposable tree. Keeping the new Jenkinsfile with the old-only adapter is expected to reject the source lock; never delete a check to make rollback green.
4. Preserve all manifests and evidence versions. No Git push or production source switch is implied.

## Guard audit boundaries

The guard code and every numeric limit remain exactly as accepted in 4de943b. Its default production delegate and original production formula are unchanged. Existing tests verify ordinary owned process-group termination and cleanup; they are insufficient to certify execution safety.

New controlled tests demonstrate three unresolved risks:

- A detached descendant can escape the tracked process group, while `processGroupStopped` is reported true. A cgroup or equivalent verified descendant containment strategy is needed before execution. The disposable escaped test process is explicitly stopped and checked before test-directory cleanup.
- Cache metadata reads follow an inner symlink outside the cache subtree. Recursive removal does not follow that symlink, but reads need a verified no-follow boundary; assertOwned and pathname operations also have a race window.
- Domain coverage and peak attestations depend on trusted caller evidence. The code cannot discover omitted physical backing domains, certify a caller's PROVEN string or prevent arbitrary concurrent writers. Monitoring alone cannot prevent a burst from crossing the hard floor between samples.

Other required controls include a final pre-spawn bound check, pinned executable identity, non-retry failure behavior, storage-identity continuity and cleanup proof. Existing checks help but are not a kernel-enforced quota or an exhaustive process-tree proof. These findings are not repaired by changing a free-space threshold.

## Existing-capacity decision

Use separate refresh and scan budgets. Do not add guest free bytes to Mac/APFS backing free bytes; containerd/overlay/cache directories can share one physical device. A 5Gi PVC declaration is not an enforced local-path quota.

- A: existing compliant DB scan is unavailable while either DB is stale, full integrity is unproven or scan peak is unknown. Do not use skip-update flags to bypass freshness.
- B: bounded refresh remains unavailable without peak, instantaneous-write, cleanup, other-writer and host-COW bounds above unchanged hard floors.
- C: independent work/cache directories may improve isolation but add no capacity, can duplicate DB storage, and change the frozen path/topology. They require separate compatibility and space proof.
- D: remain blocked. The next engineering action is validation-guard containment/path hardening under the same fixed numeric limits, with no scan/refresh activation. Space and freshness blockers remain independently in force.

Full current evidence and verdicts are in the new compatibility-capacity-review report. Runtime remains 14/16 and INCOMPLETE. STOP.

## Delivery boundary

This round records only the scoped compatibility files in a local commit, with no push. Much of the pre-existing Policy/Runtime implementation is still untracked in this workspace. This local commit is not a self-contained release checkout and does not authorize publishing that unrelated implementation. The replay receipt records the actual workspace source identities; production Jenkins remains pinned to its existing source revision.
