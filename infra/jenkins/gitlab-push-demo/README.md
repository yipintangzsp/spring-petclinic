# Isolated GitLab Push → Jenkins verification

- Project 12: root/petclinic-platform.
- Only branch: security-demo/gitlab-push-20261105.
- Only changed file: docs/security-demo-gitlab-push.md.
- Commit: 37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b.
- New Job security-gitlab-push-demo: fixed inline sandboxed Pipeline, agent none,
  no checkout, shell, scanner, credentials, registry or deployment.
- New webhook ID 5: exact branch filter and dedicated secret authentication.
  Original production hook 4, its main filter, Job and credentials are unchanged.
  Existing management authentication stayed in the operator context; the new
  Job never received it. No user, credential scope or permission changed.

Exactly one real Git push ran, exit 0. The 721-byte incremental bundle contained
only the documentation commit based on already audited #270 source. Main was
not pushed; the Jenkins Build API was never called.

Original delivery 336 (HTTP 200) automatically started
[build #1](http://jenkins.devops.local/job/security-gitlab-push-demo/1/),
which FAILED because this installed plugin does not export cause.data into
the Pipeline JSON wrapper. This genuine failure is retained.

Only the demo definition was corrected to verify the actual exported GitLab
repository URL, fixed branch, action and pinned commit. GitLab resent the same
stored event with its request body unchanged. Redelivery 337 returned HTTP 200
and automatically started
[build #2 SUCCESS](http://jenkins.devops.local/job/security-gitlab-push-demo/2/).
There was no second push, fabricated payload or manual Jenkins build. This is
not first-attempt success; the page explicitly displays the repair/redelivery.
It does not claim production main auto-publication was verified.

Both recorded build Causes identify project 12, the fixed branch and the same
commit. No GitLab branch pipeline was created, since unchanged CI rules only run
on main. Local and remote task-owned temporary Git directories were removed.

Evidence: evidence/2026-11-05/gitlab-push-demo/verified.json, push-result.json,
redelivery.json and production-health.json. The existing Overview links the
test commit and both builds as HISTORICAL evidence with event/build times.

Do not rerun push-once.py: its exclusive attempt marker rejects a second push.
The template contains placeholders for the fixed commit/repository; the
installed Job remains pinned to this single experiment.

Rollback, if separately desired: remove only webhook 5 and this demo Job after
ensuring no build is running. Do not alter hook 4 or production Jobs. The branch
remains as evidence; deleting it is a separate Git write and was not performed.
No production rollback is needed. No release or rollout.

## Restricted real Gitleaks closure (2026-11-05)

The current definition extends the existing demo Job, rather than creating a
second scanner/Policy implementation. It binds only the dedicated credential
`security-gitleaks-demo-ssh`, with its private key handled by Jenkins credentials
binding. Its key on devops is restricted by the existing server-side forced
command, `restrict`, no PTY and no forwarding. The credential store has no
Job-level isolation; the credential name and docker group are not security
boundaries. Jenkins built-in retains its pre-existing root-equivalent Docker
access; it executes only fixed reviewed dispatcher code, never repository code.
The actual scanner runs as UID/GID 24021 with no Docker/Kubernetes authority.

One additional authorized documentation-only Push advanced only the same test
branch to `d21b1271982bd4d8d90857b889c312d522779fc2`. Delivery 338 HTTP 200
started #3, which failed before scanning: the dependency packer included the
local opt-in file and the infra-only boundary rejected it. The correction only
excluded non-infra files from packaging. GitLab resent its unchanged stored Push
(event 339 HTTP 200), automatically starting [#4 SUCCESS](http://jenkins.devops.local/job/security-gitlab-push-demo/4/).
No Jenkins Build API or second Push was used in this round.

#4 performed a real fixed Clean scan over SSH, Gitleaks exit 0, zero findings,
Policy PASS, evaluationCount 1. Run ID:
`web-655884ff-c600-400f-95e8-e7b92df6340a`.
Result Digest:
`789a123c845eb9eff0f123e8f13cc637fff1af004d8db6e1674bb1e78f78d506`.
The echo-only Demo Publish executed; no production publication happened.

`run-clean.mjs` is a fixed dispatcher and reuses `acceptLinuxGitleaksPacket`
from the existing Web adapter for all sealed/raw/result/identity verification.
The SSH recipient produces Policy once; receipt validation never evaluates it.
The package is hash-pinned, shipped inline in the sandboxed fixed Pipeline,
unpacked into an exclusive demo workspace, then removed after JSON archiving.
No scripts from the GitLab commit are run. Source template placeholders are
rendered by the task's installation script, not external Job parameters.

Source evidence: `evidence/2026-11-05/gitlab-gitleaks-autoclose/verified.json`.
The existing Pipeline Overview displays it as HISTORICAL / REAL controlled scan,
with the commit, webhook delivery, #3 failure, #4 result and archived receipt.
Earlier independent Finding #3 under `security-gitleaks-demo` remains separate;
it is not a GitLab-triggered Finding claim.

Rollback: wait for this demo to be idle, restore its exact private pre-change
config backup (path/hash in job-installed.json), remove only the newly appended
public key and delete only `security-gitleaks-demo-ssh`. Preserve existing Mac
key, account, forced entrypoint and old histories. The authorized_keys backup is
root-private on devops; no credential private key is in the repository. No sshd,
Docker, production service, Gate or workload restart is required.
