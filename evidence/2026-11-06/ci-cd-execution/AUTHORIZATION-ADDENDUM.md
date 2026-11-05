# One additional permission needed; the three approved changes remain authorized

No account, token, Jenkins credential, Git push or new scan was created. Stop
before enabling the writer: the proposed UID 24022 cannot independently read
the actual Gate result. Kernel-identity read probe failed; both unauthenticated
Jenkins build and archive GETs return 403. A caller-supplied PASS/result checksum
alone is insufficient proof of real execution. The earlier plan omitted this
readability dependency; no permission check or Gate is waived to work around it.

## Exact addition requested (not implemented)

Permit updating **only the already dedicated Jenkins scanner public-key line**
in `/var/lib/security-gitleaks/.ssh/authorized_keys` to use a new root-owned fixed
wrapper `/usr/local/libexec/security-gitleaks-ci-proof.py`.

- Preserve `restrict`, all forwarding/PTY prohibitions and the same strict
  clean-v1/finding-v1 + UUID command whitelist. Preserve every other key,
  especially the Mac scanner key. Do not modify sshd or restart a service.
- The wrapper runs the existing root-owned `ssh-entry.py` exactly once as
  UID/GID 24021, preserves its timeout/output bounds, and forwards its unchanged
  packet. It does not change Gitleaks, fixtures, facts, severity, Policy or Gate.
- Only after actual successful completion, export a minimal non-secret receipt
  (Run ID, timestamps, exact tool hash, exit status, finding count, Policy result,
  evaluation count, fact/result/artifact digests) into a **new** fixed receipt
  directory. No raw Secret, production credential or Git token is included.
- Proposed directory: `/var/lib/security-gitops-demo-proofs`, owner 24021,
  group 24022, mode 02750. Receipts use validated UUID names, O_EXCL / O_NOFOLLOW,
  mode 0440; scanner creates, writer reads, other users cannot create/replace
  proofs. Do not change original scanner outputs mode 0700 or grant group
  access to the existing private evidence tree.
- The writer must validate the protected proof's ownership/type/digest, freshness,
  real Clean/PASS/exit0/single-evaluation, pinned trigger/build context and unused
  Run ID before UPDATE; consume it once and bind UPDATE/RESTORE to the same run.
  Client JSON alone, fake PASS, old/reused proof, FAIL, wrong field/ref/path and
  concurrent branch changes remain denied. Validate this addition before enabling
  the approved Git writer. No new daemon, endpoint, Job, Runner or Agent.

Rollback: restore the exact backed-up Jenkins public-key line, preserving other
entries; confirm original restricted scanning still works; remove only the new
wrapper and its task-owned non-secret export files after active tasks finish.
No production service restart, original evidence deletion or Gate rollback.

Pending this addition, do not create otherwise unusable credentials or present
the earlier independent CI and CD records as a new same-run execution. The
existing three approvals need not be requested again.
