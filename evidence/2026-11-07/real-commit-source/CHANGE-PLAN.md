# Real Commit source: bounded preparation and credential gate

Baseline a1d17b36. No new Push, build, source download or scan has occurred.

## Current facts

`python-fixture` maps to private GitLab project 12, `root/petclinic-platform`, branch `security-demo/gitlab-push-20261105`, currently at d7faa2a512ff00b88ac3a3848fa71292b3095819. This is a logical Manager project mapping, not a separate GitLab repository. The tree has 938 entries; its last page alone has 38 regular files. Existing Gitleaks approval permits only SYNTHETIC_NON_RELEASE_DIR_SCAN and 16 files / 64KiB each. Do not bypass or silently reinterpret that approval as a real repository scan.

The previous CI token, UNIX bridge and SSH wrapper were removed. User 4 remains active, non-admin, with only project 12 Developer membership. It has no active token; no dedicated source-read token is present. Existing management GET access is not permission to hand its administrator credential to the scanner or Jenkins.

## Pending approval requested

Create a short-lived `read_repository` credential for the same existing user 4, using the existing legitimate management entry only for this scoped issuance. Preserve its single project membership. Store only on the restricted server, root0440/GID24021 or narrower; never give the token to Jenkins, the browser, a source file, log or Artifact. Revoke and remove it after the bounded attempt. Restore the same previously approved one-run CI-only UNIX bridge and exact Commit/Build capability, with <=1h expiry; no LAN/TCP listener, new identity, broad SSH access or sshd change. No credential has been created pending this approval.

## Minimal implementation after authorization

1. Preserve old Fixture operations, limits and approvals. Add a distinct explicit REAL_COMMIT_SNAPSHOT input mode to the existing Runner/Adapter with root-owned project/repository/branch mapping; no second scanner or Policy Engine.
2. The trusted source phase, running nonprivileged, fetches the fixed GitLab branch using the read-only credential and fixed Git arguments/environment (no hooks, no caller URL/ref/path). The requested full SHA must equal the fetched allowed branch tip. Validate its Git commit object and root tree. Enumerate Git-tree blob OIDs, modes and safe relative paths server-side; never accept this manifest from Jenkins.
3. Obtain a bounded archive for that exact commit from the fixed repository. The source-input helper verifies every file's Git blob OID, full expected file set, duplicates/types/paths and compressed/expanded limits before exclusive materialization. Reject symlinks, hardlinks, devices, submodules, path traversal, incomplete exports or an unknown Git object. Retain Git commit/root-tree identity, archive SHA256, per-file SHA256 manifest and scope; no source contents in logs or result metadata.
4. New real-source bounds must be explicit and finite, checked before scanning. Proposed per-project ceiling: 1500 regular files, compressed archive32MiB, expanded96MiB, file4MiB. These are not production Gate changes. If actual source exceeds them or contains unsupported entries, stop; do not scan a silently reduced subset or repeatedly raise limits. Existing CPU/memory/disk guard and fixed Scanner SHA/config/timeout remain.
5. Gitleaks scans those actual verified bytes through the existing Registry/Core/Policy/Router. Do not mark Fixture as real Commit. Remove source snippets/secret-bearing native fields from anything exported; retain safe locations/rule IDs/counts and original native-report hash. Policy FAIL must reach Jenkins as FAILURE, not an executor error. Source acquisition and scanner errors stay distinct.
6. Review fixed CI script; perform at most one new documentation Push on that isolated branch and one automatic run, no manual build. Verify actual GitLab event and Jenkins Cause/Commit. Keep production Hook4 main filter and production Job unchanged. Previous #8 remains a separate Fixture history.
7. Reuse current UI to show SOURCE_MODE=REAL_COMMIT_SNAPSHOT, actual Commit/snapshot hash, source cleanup, CI context, Run ID/Policy/Result Digest and actual Loki/Grafana proof. No Dashboard change. Clean temporary source and credentials, restore single-run entry/channel, preserve immutable result.

## Work completed without the credential

`ci/source-snapshot.py` is input verification only: no network, scanner, credential or Policy. Six SYNTHETIC_UNIT_ONLY tests verify exact Git blob bytes, traversal rejection, symlink rejection, wrong content rejection, incomplete tree rejection and non-overwrite of history. This is not proof of a real GitLab Commit binding or a successful scan. It is not connected to production or an active Runner yet.

## Rollback

Unwired helper may be reverted without online effect. Once approved live setup is performed, revoke only its read token and one-run capability, remove only the validated temporary snapshot directory and socket, restore only task-specific SSH/Job changes from private backups, retain sealed evidence and old Fixture/SBOM/Policy/Loki/Dojo records. No production change or rollback is included.
