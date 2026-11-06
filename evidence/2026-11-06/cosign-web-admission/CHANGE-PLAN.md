# Cosign Web: minimal additional authorization (NOT EXECUTED)

Target: existing devops host 192.168.64.11, via the existing strictly verified SSH management alias 192.168.1.58. HEAD 924cf5d2.

The user's current request requires approval before creating a new restricted Linux identity/SSH entry. Previous authorizations name only security-gitleaks and security-semgrep. Neither identity will be extended.

## Requested scope

1. Create security-cosign, system-selected unused UID/GID, locked password, sole private group, no sudo. Proposed creation command, after checking passwd/group/home conflicts:
   `sudo -n /usr/sbin/useradd --system --user-group --no-create-home --home-dir /var/lib/security-cosign --shell /bin/sh security-cosign`
2. Restore root-owned release directory `/var/tmp/security-manager-gitleaks-cosign-web-20261106` (the prefix is required by the existing frozen Cosign Runner contract). Copy the existing fixed offline tool and the existing four public test fixture files; reuse existing Manager/Runner/Policy/Router modules. Root-owned input directories 0555, files 0444, executable 0555. Only dedicated outputs 0700 belongs to the new UID. No new Cosign signing key or signature generation.
3. Create a dedicated Mac SSH transport key `~/.ssh/security-manager-v2-cosign` (0600, never repository/log/page), and install only its public key in `/var/lib/security-cosign/.ssh/authorized_keys` (0640 root:new-group, directory 0750 root:new-group). Proposed key restriction:
   `restrict,command="/usr/bin/python3 -I /var/tmp/security-manager-gitleaks-cosign-web-20261106/ssh-entry.py" ssh-ed25519 <dedicated-public-key>`
   Forced entry permits only `valid-v1 <web-UUID>` and `invalid-v1 <web-UUID>`, with two fixed approved object IDs. No caller paths, shell arguments, stdin, PTY, forwarding or arbitrary images. Sanitize environment, NoNewPrivs, no capabilities, retain bounded resource/time/output checks. No global sshd configuration or service restart.

## Existing material, checked read-only

- Tool: existing Jenkins offline tool bundle `/var/lib/rancher/k3s/storage/pvc-14c139bf-5717-4b2f-9997-4c77fa03f409_ns-devops_jenkins-pvc/platform-security/20261027/cosign`; pinned version 3.1.4, SHA256 `ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2` matches scanner-tools.json.
- Public fixture archive: `evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/cosign-fixtures/`.
- Valid object java-fixture-valid.json SHA256 `d6d0bbaaef787bd7de7d776ca408060d4745b01e6136843505558caf6231aaca`.
- Tampered object java-fixture-tampered.json SHA256 `90564abcbe4aa3395e7ceb7ab598778b1e64a299d285a7097afe94e0e2e2f480`.
- Existing shared test signature java-fixture-valid.sig SHA256 `2050c91b38871262920bcc8a4efe9025aaf43500efc8d90860d4efb3c81aa44b`.
- Existing test public key java-fixture.pub SHA256 `053e9751b649590ba28ac9e57eb3f4b09304eefa0987db939a1598225d6c923d`.
- Historical actual native Cosign reports bind these inputs, with exits 0 and 1 respectively. These are HISTORICAL, not new Web executions.

## Execution after approval

Verify permissions and command/forwarding rejection, connect minimal local Web adapter, then exactly two fixed offline verifications through the existing API. Existing Policy evaluates once each. Export sealed reports into existing local run persistence; verify PASS/FAIL, unique Run IDs/digests, page/API access and persistence. Do not activate production Security Manager or modify production Gate.

## Rollback

Disable only the new Cosign Web opt-in and restart only the local page after checking no active task. Revoke only the dedicated Cosign authorized_keys. Verify no process remains under the newly allocated UID; then `sudo -n userdel security-cosign` and, if it remains unused, `sudo -n groupdel security-cosign`. Remove only the two exact newly-created Linux directories above and the dedicated Mac SSH key pair. Preserve historical evidence and all Gitleaks/Semgrep files. No production service restart, push, release or rollout.

Status: AWAITING_EXPLICIT_AUTHORIZATION. None of the proposed privileged changes has been executed.
