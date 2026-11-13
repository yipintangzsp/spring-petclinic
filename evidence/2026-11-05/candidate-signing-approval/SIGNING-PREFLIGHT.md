# Candidate signing / release approval — BLOCKED

Read-only observation: 2026-11-05 23:32:47 +08:00. Local HEAD `7fa2c30c`.
No job started, signing performed, image rebuilt, credential exported, GitOps changed,
push, release, sync or rollout. Existing uncommitted work and historical evidence preserved.

## Exact missing evidence

`observed.json` records LIVE registry HEAD results with repository pull scope:
candidate index `sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55`
and its ARM64/AMD64 child signature tags all return 404. These are the legacy
`.sig` tags consumed by the existing workflow; this is not a claim that all possible
OCI attachment formats were enumerated. No actual Cosign signature verification
can be claimed from HEAD results.

`petclinic-ci #270` remains SUCCESS, with no active/queued run. Its exact candidate
and source are bound in the archived summary, whose SHA256 remains
`ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8`.
`PROMOTION_ACTION=audit-only` skipped candidate approval/signing, not the existing
`securityManager(mode: 'enforce', adapter: 'petclinic')` invocation. Do not call
that archived security result an approved release. The build lacks
`candidate-sbom.json`, `approval-signing.json`, `approved-release.json`,
`approved-release.sig` and `promotion-result.json`.

Live Job definition SHA256 remains
`abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25`.
Protected GitOps main remains `340ef4b8c74e3c2a5820da8d98b0f134283bb8d9`.
This preflight did not repeat application or node health checks and does not
claim fresh production health from historical snapshots.

## Existing implementation and authorization conflict

Reviewed source: `9a78cc89f22fa98fb1ffcc43e2ae279299471793`.

- `Jenkinsfile.security-audit`: `dry-run` executes the full existing PetClinic
  enforce adapter, candidate SBOM, then Candidate Sign and Approve.
- `infra/security/promotion/sign-approve.mjs`: uses existing `platform-signing-age`
  and `harbor-creds`; signs and actually verifies the exact candidate index and
  both children against `infra/security/cosign.pub`. Signs/verifies approval JSON;
  removes temporary copies of the existing key. No candidate rebuild.
- `infra/security/promotion/promote.mjs`: rejects approval from another build,
  source or candidate. Its `dry-run` branch does not commit/push or deploy;
  generates a patch only in a disposable clone and archives evidence in Jenkins.
- However, the mandatory existing adapter first executes `signing.mjs admission`:
  writes three test manifests to `petclinic/signature-fixtures`, signs fixtures,
  and **generates a fresh wrong-key private key** for a negative admission test
  (line 81). This violates this round's explicit no-temporary-private-key scope.
- The same adapter also submits existing Harbor Trivy scans, Sonar analysis,
  imports/reimports into DefectDojo (including the existing false-positive
  verification PATCH), and executes other existing security/regression checks.
  These are outside this round's signing/approval-only scope. No stages may be
  skipped or historical results injected to force an approval.

## Exact additional approval needed to reuse the existing path

Authorize **one** existing `petclinic-ci` run, pinned to the reviewed source,
with `PROMOTION_ACTION=dry-run`, including its unchanged complete enforce adapter,
existing ephemeral wrong-key admission negative test, fixture registry writes,
Harbor scans, Sonar analysis, existing Dojo import/governance writes, resource
lease/cleanup, and existing signing identity for candidate signatures and approval.
No new credential, signing service, IAM permission or signing trust root is proposed.
This is an expansion of execution scope, not a request to waive a Gate.
If the no-new-temporary-test-key prohibition must remain absolute, this existing
unchanged pipeline cannot be used; do not execute it or invent a sign-only bypass.

Fixed inputs after such approval (revalidate Job definition and absence of concurrent
work first; fail closed on any change):

```text
Source = 9a78cc89f22fa98fb1ffcc43e2ae279299471793
PROMOTION_ACTION = dry-run
AUDIT_CANDIDATE_IMAGE = core.harbor.domain/petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55
ENABLE_IMAGE_BUILD_PROVENANCE = true
ENABLE_PROVENANCE = false
BUILD_PROVENANCE_EXPECTATION = {"commit":"9a78cc89f22fa98fb1ffcc43e2ae279299471793","repository":"http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git","builder":"http://jenkins.devops.local/job/petclinic-candidate-build","buildNumber":"2"}
```

Completion requires actual successful enforce evidence and existing Cosign verify
for all three exact digests, approval verify-blob, matching source/build/candidate,
successful existing build-provenance verification, private-file cleanup, and
`DRY_RUN_PASS` / `NOT_REQUESTED`. Reconfirm unchanged GitOps main, runtime digest,
Deployment and Argo state. No deployment is authorized by this proposed run.

Current verdict: `RELEASE_READY=NO`; signatures/approval not generated or verified.
Stop pending the explicit execution-scope approval above. No rollback is needed
because no production/signing mutation was executed.
