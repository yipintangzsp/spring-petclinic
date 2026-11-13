# Trivy guard Phase 1 acceptance

GUARD_PHASE1_IMPLEMENTATION_VERIFIED (guard implementation scope only).

- Guard: Darwin ARM64 73/73; Linux ARM64 Node20.19.2 73/73.
- Existing regression147/147, Runtime143/143, Policy core5/5, contract10/10.
- 13 controlled disposable Node process cases per platform; no Trivy execution.
- Original production guard, callers, Gate and Summary unchanged byte-for-byte; no production activation.
- Fixed validation floor uses existing 15%+8GiB stop line, plus full explicit peak/burst/cleanup/other-writer budget.
- Monitor/termination/owned cleanup tested. Both Linux source staging trees confirmed removed.
- Initial local regression EPERM corrected by allowing local loopback test listeners; failure log retained.
- First Linux failure was a sample-count timing race in the final-state fault fixture; now explicitly injected at final sampling, no weakened guard; failure and cleanup evidence retained.
- Strict current-tree frozen Trivy differential: 2/190 pass, 188/190 fail due the already accepted Helm Jenkinsfile raw SHA delta. Historical lock unchanged; no runtime Policy compatibility claimed. See frozen-source-diagnosis.json.
- Peak upper bound is not proven; controlled Trivy executions0, release0, rollout0.

Next action: only a real read-only budget precheck. No real refresh may start without the complete proof.
