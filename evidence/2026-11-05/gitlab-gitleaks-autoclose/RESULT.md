# GitLab → Jenkins → restricted real Gitleaks — completed

- Authorized changes: one dedicated Jenkins SSH credential and one restricted
  public key appended to the existing account. Private key stayed inside Jenkins.
  Existing authorized_keys entries, sshd and production credentials are unchanged.
- Exactly one test-branch Push: d21b1271982bd4d8d90857b889c312d522779fc2.
  Only docs/security-demo-gitlab-push.md changed. Main/GitOps were not pushed.
- Hook #5 event 338 HTTP 200 automatically started #3. Packaging boundary
  correctly blocked a local opt-in file before scanning. Original failure saved.
- Excluding non-infra dependencies fixed the package. GitLab resent the same
  authentic stored Push, event 339 HTTP 200, and automatically started #4.
  No second Push, fabricated event or Jenkins Build API call.
- #4 SUCCESS: real Gitleaks v8.30.1, UID/GID 24021, exit 0, findings 0,
  Policy PASS and exactly one evaluation; sealed/raw/fact/result digests verified.
- Run ID: web-655884ff-c600-400f-95e8-e7b92df6340a.
- Result Digest: 789a123c845eb9eff0f123e8f13cc637fff1af004d8db6e1674bb1e78f78d506.
- Demo Publish executed only echo. No image/GitOps/deployment operation.
- Overview HTTP 200 twice, same content; new result visible as HISTORICAL / REAL,
  not a fabricated Web request. Authenticated Jenkins build/artifact GETs HTTP 200.
  Original Web Clean PASS/Finding FAIL remain readable. Browser click NOT_TESTED.
- Fresh production snapshot 2026-11-05T14:10:59Z: all nodes Ready, PetClinic 3/3,
  HTTP 200, Argo Synced/Healthy, generation 175/image unchanged, socket 0660.
  Jenkins #270 SUCCESS, production definition/V1 Summary exact hashes unchanged.
- Arbitrary SSH command / PTY / forwarding were actually denied before scanning.
  Jenkins credential ID is not Job isolation. Server forced command remains the
  primary boundary; built-in Docker-equivalent residual authority is unchanged.
- No production release/rollout. Production Security Manager NOT_ACTIVE;
  Canonical Runtime 14/16; Original Evidence Integrity FAILED remains unchanged.

Proof: verified.json, observed-first.json, observed-redelivery.json,
ssh-boundary.json, production-health.json, page-http.json, visible-links.json.
Backups and exact rollback are in CHANGE-PLAN.md, job-installed.json and
 authorized-key-added.json. No rollback was required. No additional permissions.
