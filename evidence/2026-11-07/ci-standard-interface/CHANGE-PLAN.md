# CI standard interface: bounded authorization required

Baseline 5970958c. Read-only live inspection only; no Push, Job/credential change or scan.

## Verified blocker

- Project 12 Hook 5 still targets security-gitlab-push-demo, fixed branch security-demo/gitlab-push-20261105.
- The Job is idle, last build #6 SUCCESS. Its fixed scheduler invokes the scanner SSH entry and contains run-cd.mjs; it does not call a Manager API. Existing #6 is not this task's evidence.
- Jenkins has security-gitleaks-demo-ssh and security-gitops-demo-ssh; neither is a project/plugin-scoped Manager credential.
- The former key is forced to /usr/local/libexec/security-gitleaks-ci-proof.py. Its authorization is fixed scan plus Gate receipt, not a new Manager submission/proxy command.
- Mac Manager binds 127.0.0.1:17862. Its project grants currently cover only java-sbom-demo and java-sbom-demo-b (SBOM). Do not export their tokens or the operator credential to Jenkins. The localhost browser intake is not a CI authentication contract.

## Exact additional scope to approve before implementation

1. Grant the existing Jenkins scanning SSH principal a dedicated, expiring Manager CI capability. Fixed project python-fixture, plugin gitleaks, scene clean; submit plus read its own run only, max one admitted execution, expiry <=1 hour. No operator, SBOM, other plugin/project, configuration-write or publication rights. Keep any HTTP capability in a protected server-side file (root-owned, 0440 to UID/GID 24021), never in Git, Jenkins logs or Artifacts. No new OS identity, group or production credential.
2. Extend only that existing public key's root-owned forced wrapper with a fixed `manager-ci-v1` operation. Accept bounded JSON containing the standard CI identity fields; validate fixed repository/project/test branch/Job and the pre-bound trigger Commit. Preserve existing scan/Gate-receipt operations and the Mac key unchanged. Retain restrict, no shell/PTY/agent/TCP forwarding. No arbitrary paths, URLs, scanner options or commands. Jenkins built-in still runs only the reviewed scheduler, not checkout scripts. The globally stored Jenkins credential is NOT strict Job isolation; server authorization limits it to the fixed project/plugin regardless of client-supplied Job labels.
3. Permit a single-build temporary, private UNIX-socket SSH bridge to a CI-only intake in the existing Mac Manager process. Proposed Mac socket: the existing owner-private control state directory, `ci.sock`. Proposed remote socket: /var/lib/security-gitleaks/ci-channel/manager.sock. Directory owned by the existing SSH tunnel operator, traverse only to GID 24021; socket 0660 for that group. This is new filesystem/channel access and must be explicitly approved. Verify existing SSH server permits stream-local forwarding without changing sshd; otherwise STOP. Do not forward the full browser endpoint, listen on a Linux TCP port, bind 0.0.0.0, expose the LAN, add a daemon, or broaden the scanner key's forwarding rights. Remove the exact socket/channel after the build; failure to prove its boundary or cleanup blocks execution.

The CI-only intake must authenticate before any operation, consult the current authoritative Manager global/project/plugin controls, reject arbitrary command/path/scanner parameters, call the existing Runner/Policy/Router once, and return the sealed Result Digest without reevaluation. The bridge must not expose the browser API or two SBOM projects. No stale Linux configuration copy may override a current Manager disable.

## Already-authorized work after the above scope is approved

- Reuse Job security-gitlab-push-demo and Hook 5. Preserve its exact definition hash 3480fb1418a7d790a05d334f43b58df382ac52d81557ae5f203690093f73e6ff and rollback configuration privately before mutation.
- For this run use only identity verification -> Manager request -> consume Policy -> archive -> echo. Omit all GitOps/update/restore and production publication operations. Do not bind the GitOps credential.
- Standard envelope: projectId, sourceRepository, commitSha, ciProvider, jobId, buildId, trigger, pluginId, fixed scenario. Source context is trigger metadata, not proof that the GitLab checkout was scanned: execution scope remains the approved Clean fixture.
- One controlled Push only to the existing isolated branch after verifying hook/Job isolation; no main/GitOps Push. Real Webhook Cause and Commit/Build correspondence must be checked against Jenkins/GitLab records, not accepted solely from client strings.
- Disabled/unauthorized negative checks start no scanner. One actual Clean -> Policy PASS -> Router -> Loki/Grafana -> existing page. No Agent/plugin/SDK/database/queue.

## Rollback

Wait for the bounded run to terminate; revoke/delete only the new CI capability file, terminate only the recorded temporary tunnel, remove only the verified newly created socket and directory, restore only the changed Jenkins-key forced-command line and the captured demo Job definition. Stop/unlink the CI-only Mac socket. Preserve all other keys, project grants, historical runs, Hook 5, production Jobs, Docker, Kubernetes, V1 Summary and GitOps. If any permission or socket boundary cannot be proved without broader rights, do not execute the Push.
