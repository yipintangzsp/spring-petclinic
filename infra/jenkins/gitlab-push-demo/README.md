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
