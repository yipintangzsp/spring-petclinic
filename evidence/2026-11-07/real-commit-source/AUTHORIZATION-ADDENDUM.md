# Exact source-input deployment requiring approval

2026-11-07. HEAD before changes 83ddac41. Read PAT id5 exists on restricted server; no new Push or real scan. User separately approved one short-lived write_repository PAT for existing user4 and one isolated test-branch Push.

## Direct blocker

Git archive applied text conversion to gradlew.bat and mvnw.cmd. 830 Git blobs were enumerated. Exact byte verification correctly rejected the export. The input helper now builds a canonical bounded tar from git cat-file --batch blob bytes, verifies each blob OID and the entire root tree, and then invokes the SAME existing Gitleaks Runner and Policy. No checkout hooks/build scripts run.

Automatic review rejected replacing root-owned source-snapshot.py under the earlier read-only credential/channel wording. No retry/deployment is permitted until this exact addendum is approved.

## Exact additional deployment scope

Host devops / 192.168.64.11, verified host key alias192.168.1.58. No account, sudoers, groups, sshd, Docker, Kubernetes or production changes.

1. Root writes the reviewed input helper, fixed source wrapper, root-owned immutable Manager package and per-file SHA manifest under ONLY `/var/tmp/security-manager-gitleaks-realcommit-20261107/`. Approval.json pins project python-fixture, project12, fixed test branch, ONE prepared full commit SHA and Git root tree, existing Gitleaks tool identity, UID24021, <=1h expiry and the bounds in CHANGE-PLAN. Inputs/outputs private to existing UID24021. Original Fixture approval and tools stay unchanged.
2. Backup `/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py` to a unique adjacent task backup, then add ONE early fixed `commit-v1 <web-uuid> <low|standard|strict>` dispatch to the new source wrapper. Preserve legacy Clean/Finding logic and both public keys. No arbitrary URL/ref/path/command. Exact commit/repository/branch supplied by root approval, not SSH/Jenkins arguments.
3. Restore the previously approved temporary Jenkins-only manager-ci dispatch for its existing key, exact-CI capability and private UNIX bridge. Backup authorized_keys independently. No new key, LAN/TCP listener or SSH privilege. Nonproduction Job definition temporarily calls same standard Manager API and is restored afterward.
4. Local changes use existing Adapter/Core/Registry/Policy/Router/UI. Commit metadata, snapshot SHA, cleanup and safe findings only are exported; raw Match/Secret/source bytes never leave the restricted source workspace. Preserve Policy FAIL as a real Gate failure.

Only root-owned installation uses the existing management entry. Actual fetch/scanning remains existing nonprivileged UID24021, no Docker/sudo/Kubernetes access.

## One-run action after approval

Use already approved separate read/write credentials. Prepare exactly one documentation commit on security-demo/gitlab-push-20261105; verify only docs/security-demo-gitlab-push.md changes and main stays unchanged. Pin its Git objects in root approval and Manager capability; lint and inspect fixed Jenkins definition without starting a build. One Push, one webhook-triggered real source scan, no manual build/retry, no publishing or GitOps. Bound input 1500 files,32MiB archive,96MiB expanded,4MiB/file. Existing resource gates unchanged; errors stop.

## Rollback / cleanup

Stop exact recorded tunnel PID, remove only its sockets/capabilities; restore task-backed-up Job definition and scanner SSH entry plus authorized_keys. Revoke read PAT id5 and the separately recorded new writer PAT via the original management entry, remove their private files/askpass and trigger bundle. Remove only task-created source Git/workspaces; keep nonsecret sealed result and original history. No production rollback required because no production resources are changed. If deployment validation fails before Push, restore immediately and do not Push.
