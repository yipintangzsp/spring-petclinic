# Authorized Semgrep-only restore
Target: existing devops / 192.168.64.11, strict host-key alias 192.168.1.58.
Create system-selected UID/GID security-semgrep, locked password, sole private group, no sudo.
Root-owned /var/lib/security-semgrep/.ssh/authorized_keys uses restrict + fixed Python entry; no sshd changes.
Root-owned /var/tmp/security-manager-gitleaks-semgrep-web-20261106 contains pinned offline Semgrep 1.182.1, original rules, two passive Java fixtures and existing Candidate modules. Only outputs is account-writable (0700).
Dedicated Mac key ~/.ssh/security-manager-v2-semgrep; never logged or committed.
Only clean-v1/finding-v1 plus UUID accepted; original Gitleaks identities/keys untouched.
Two Web API scans, existing Policy once each, local-only Router.
Rollback: disable dedicated Semgrep opt-in and restart local view; remove only its authorized_keys; after verifying no account processes, remove this new account/group and these two exact dedicated directories. Remove only the new Mac key pair. No production service restart, Git push, release or rollout.
