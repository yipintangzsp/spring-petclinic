# Controlled Jenkins Gitleaks demonstration

Verified 2026-11-05 (Asia/Shanghai):

| Build | Scanner | Policy | Jenkins | Demo Publish |
| --- | --- | --- | --- | --- |
| [Clean #2](http://jenkins.devops.local/job/security-gitleaks-demo/2/) | exit 0, 0 findings | PASS | SUCCESS | Echo only |
| [Finding #3](http://jenkins.devops.local/job/security-gitleaks-demo/3/) | exit 1, 1 controlled finding | FAIL | FAILURE | Skipped |

Both are new REAL executions on devops/192.168.64.11 as security-gitleaks
(UID/GID 24021), Gitleaks v8.30.1. Each uses the existing runner and exactly
one existing Policy evaluation. No checkout, image build, registry push,
GitOps update or deployment occurs.

The bounded Mac dispatcher starts the exact Jenkins build and waits for its
admin-only input. It calls the existing local Web API with CSRF protection,
validates the newly sealed result and signs a build/scenario-bound receipt.
Jenkins verifies the pinned Ed25519 signature and receipt invariants using
fixed Node code, archives the verified receipt and enforces PASS/FAIL.
Built-in receives no fixture, scanner, SSH key, production credential or
user-selected command/path. Node runs with a cleared environment.

This is an operator-assisted demo, not autonomous production CI. The scanner
SSH forced-command boundary is unchanged. Only admin can currently authenticate;
signup and anonymous read are disabled; historical non-local user records have
no API tokens. This is point-in-time evidence: adding users requires reviewing
the existing Jenkins authorization strategy before reusing this built-in design.
No permissions or ACLs were changed.

The temporary signing private key was deleted after both builds. The Job remains
viewable. Running manually without the dispatcher waits and then fails closed.
A new supervised demo rebinds a new public key. The Pipeline template contains
a placeholder, not a signing secret.

From the repository root, with existing authorized operator access:

```sh
python3 evidence/2026-11-05/security-gitleaks-jenkins-demo/run-demo.py
```

The dispatcher refuses unknown installed definitions and active demo builds,
updates only this demo Job, and exclusively creates evidence files. Setup #1
aborted before scanning because Jenkins normalized the input ID; it is not a
gate proof. Live builds #2 and #3 are the acceptance evidence.

See evidence/2026-11-05/security-gitleaks-jenkins-demo/delivery.json.
The workflow REST API labels the skipped #3 stage FAILED on this installation;
the console explicitly records `Stage "Demo Publish" skipped due to earlier
failure(s)`, with no publish echo. Use the console as the skip evidence.

The page at <http://security.devops.local:17862> has both build links. HTTP GET
returned 200; both new REAL records were re-read by API with matching digests.
Browser clicks were not automated. Jenkins build URLs require login; anonymous
HTTP GET returns 403.

Rollback: after ensuring no active demo build, remove only this Job (also removes
its build archives) and revert only the added page paragraph. No production
configuration rollback is needed. Deletion was not performed: the demo remains.

Production checked: petclinic-ci #270 still SUCCESS and latest; definition and
V1 Summary hashes unchanged. Three nodes Ready, PetClinic 3/3 and HTTP 200,
Argo CD Synced/Healthy; deployment spec/generation, image and Docker socket
0660 unchanged. No release, rollout or push. Production Security Manager stays
NOT_ACTIVE; canonical capability stays 14/16. No additional approval needed.
