# CI → CD link: exact authorization needed

Status: BLOCKED before any Push, build, scan or configuration change.
Local baseline `4a21ad41`. Existing demo remains baseline / Synced / Healthy.

## Proven missing boundary

Live credential metadata identifies the GitLab credentials visible to the existing
demo Job as `root`, and the authenticated read-only identity as GitLab administrator.
These credentials were used only for GET inspection, never for this round's Git
writes. Do not bind them to the proposed CD stage. The existing dedicated
`security-gitleaks-demo-ssh` is a forced scanner command, not a Git writer.
Exact current Job stages end in an echo-only Demo Publish. No verified restricted
GitOps writer credential/entrypoint is configured. Credentials metadata alone
must not be treated as proof that some generically named credential is safe.

The actual main protection allows Maintainers (40), with force push disabled.
This existing policy must stay unchanged. GitLab branch restrictions alone do
not restrict file paths or individual ConfigMap fields.

## Three scoped authorization changes requested, not executed

1. Create a dedicated **project 12 only**, non-administrator Git writer identity /
   access token with Developer (30), `write_repository`, short expiry (7 days).
   No API/admin scope, project membership elsewhere, Maintainer role, protected
   branch policy change, production credential replacement or broader fallback.
   If this GitLab installation cannot issue that identity, stop before creation.
2. On existing devops `192.168.64.11`, create a dedicated nonprivileged
   `security-gitops-demo` writer identity after UID/GID/name collision checks;
   no Docker group, sudo, Kubernetes credentials or system-service change.
   Keep that new dedicated Git token only in its protected server-side storage,
   never in Jenkins, repository, page or logs. Install one root-owned reviewed
   SSH forced-command entry with exactly UPDATE and RESTORE operations; no user
   shell, arbitrary command/path/branch/remote, PTY or forwarding. It must validate
   the repository, exact expected old branch head, single-file diff and manifest
   before every push. Permit only:

   ```text
   repository: root/petclinic-platform (project 12)
   branch: security-demo/gitops-20261105
   file: infra/devops-lab/gitops-demo/configmap.yaml
   object: devsecops-test / ConfigMap petclinic-gitops-demo
   only mutable field: data.demo-stage (baseline ↔ updated)
   main: DENIED (also blocked by unchanged GitLab main protection)
   arbitrary files, additional resources, force push, direct Kubernetes writes: DENIED
   ```

   UPDATE must require the same build's validated real Gitleaks PASS receipt and
   explicit trigger Commit / Run ID / Result Digest binding. RESTORE must revert
   only the recorded UPDATE Commit and reject concurrent branch changes.
   Review its exact implementation before activation; no unchecked PASS string
   or client-supplied arbitrary Git tree may authorize a write.
3. Create Jenkins SSH credential `security-gitops-demo-ssh` for that forced entry
   and append only its dedicated public key with `restrict,command=...`.
   Credential ID is not a Job-level permission boundary. The server-side
   command is the boundary. Preserve all existing Gitleaks keys and credentials.

This reuses the existing SSH forced-command approach; it does not authorize a new
Job, Agent, scanner, Manager, Application, Namespace, controller or daemon.
Jenkins built-in's already known Docker-equivalent privilege remains a separate
limitation: trusted fixed scheduling must not invoke Docker or load repository
scripts, and this change must not be described as completed Jenkins identity
isolation. No token with sufficient authority to push main is proposed.

## Work already authorized, after the new write boundary is approved and verified

Back up only the existing nonproduction demo Job definition. Retain Webhook #5
and trigger branch `security-demo/gitlab-push-20261105`. Extend its fixed trusted
definition to call the restricted writer only after the existing real Gate.
No production Job/Gate change. One new documentation Push triggers the real
webhook; no Build API. Use the existing Argo automatic sync and the existing
Application/ConfigMap. Bind actual update and restore revisions and observed
values to this build; then render that same-run receipt in the existing page.

## Rollback / revocation

If an UPDATE already happened, first restore through the writer's checked Git
revert and confirm Argo/ConfigMap baseline. Restore the demo Job's captured
definition; remove only the new writer public key and Jenkins credential; revoke
only the dedicated GitLab token and remove only task-created writer files/account
after checking active tasks and ownership. No daemon restart, production main
write, ConfigMap patch, Namespace/Application deletion or production rollback.

## Current result

No new Trigger Commit, Build URL, Gitleaks Run ID/digest, update or restore Commit
exists for this round. Earlier #4 and the previous GitOps demo remain separate
historical successes. Do not join them into a same-run CI→CD result.
Page HTTP 200; current production 3/3 / HTTP 200 / three nodes Ready;
production GitOps revision and runtime image unchanged. Release=0, Rollout=0.
Stop until the three authorization changes above are explicitly approved.
