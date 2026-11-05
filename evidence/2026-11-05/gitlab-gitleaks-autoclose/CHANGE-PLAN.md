# Jenkins → existing restricted Gitleaks: approval required

Baseline: 209c51d6. No production or demo configuration changed in this round.
No push, build or scan started.

## Direct blocker

The existing GitLab webhook and demo Job are working. Jenkins has no SSH
credential for security-gitleaks. Its only visible SSH credential is
github-petclinic-ssh, username git; it must not be repurposed. The earlier
Gitleaks demonstration explicitly used the Mac operator dispatcher to call
the localhost Web API and return a signed receipt. That is not proof that
Jenkins itself can invoke the restricted scanner.

## Exact new authorization requested

1. Generate a new dedicated Ed25519 key for this non-production demonstration
   and store it as a Jenkins SSH credential named security-gitleaks-demo-ssh,
   username security-gitleaks. Do not copy the Mac key or modify any production
   credential. Do not print the private key or commit it. The current credential
   store does not establish strict per-Job isolation; a dedicated credential ID
   must not be represented as such. Only fixed reviewed scheduling code may bind
   it. Jenkins built-in's existing Docker-equivalent authority remains a separate
   unresolved identity-isolation limitation.
2. On devops / 192.168.64.11, append only that public key to the existing
   root-owned /var/lib/security-gitleaks/.ssh/authorized_keys, after preserving
   the exact current file and its hash in a private backup. Keep all existing
   entries. Apply the same existing restriction:

   ```text
   restrict,command="/usr/bin/python3 -I /var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py"
   ```

   The key permits only existing clean-v1 / finding-v1 plus validated Run ID.
   No shell, forwarding, PTY, new account/group, sudo or sshd configuration change.

No Jenkins/GitLab ACL change, Agent, plugin, listener, Docker/K8s permission or
new scanning service is proposed. Do not open the Mac localhost API to the LAN
or introduce a privileged proxy to avoid the missing authorization.

## Already requested work, executable after approval

- Preserve webhook 5 and its exact test branch; leave production hook 4 alone.
- Add a fixed SSH call to security-gitlab-push-demo, with strict host-key checking
  using the already trusted host key. Do not fetch-and-trust a new host key or
  alter existing trusted records.
- Reuse the existing Linux runner, frozen tool/config/fixtures, Policy Engine
  and sealed artifact verification. Policy runs once; Jenkins consumes its
  returned decision and digest. No arbitrary command/path/argument input.
- Bind the permitted test Commit before pushing, then perform one isolated
  documentation Push. A GitLab webhook must start Jenkins; no Build API.
- Stop after Clean REAL/PASS/SUCCESS and an echo-only Demo Publish are verified
  and linked from the existing page. Existing independent Finding #3 remains
  labelled separately. Do not claim it was triggered by this new Push.

## Rollback

Disable only the new credential use in the non-production Job, wait for its
bounded execution to end, remove only the newly added public key, and delete
only the new Jenkins credential. Preserve the Mac key, existing authorized_keys
entries, production credentials and both original demo histories. Restore the
demo definition from its exact captured configuration if needed. Verify the
new key is refused and the existing Mac restricted channel remains intact.
No daemon or production service restart is required.

Until explicit approval: all new end-to-end execution verdicts remain INCOMPLETE.
