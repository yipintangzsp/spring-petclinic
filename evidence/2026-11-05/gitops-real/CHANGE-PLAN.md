# One ConfigMap GitOps demonstration

Approved task scope: one test branch, one Application, one ConfigMap, one update,
one actual git revert. No production mutation or new RBAC. Existing management
rights were verified; no new credential, Namespace, controller, Pod or service.

- Existing GitLab project 12: `root/petclinic-platform`.
- New branch: `security-demo/gitops-20261105` (confirmed absent).
- New path: `infra/devops-lab/gitops-demo/configmap.yaml`, only file in this
  independent demonstration branch. No production checkout or executable source.
- Existing destination Namespace: `devsecops-test`.
- New ConfigMap: `petclinic-gitops-demo`, `data.demo-stage=baseline`.
- New Application: `argocd/petclinic-gitops-demo`, existing project `default`.
  Exact repository/branch/path, directory includes only `configmap.yaml`, no
  recursive discovery, fixed Namespace. Auto-sync selfHeal enabled, prune=false,
  allowEmpty=false, CreateNamespace=false. No deletion finalizer.
- Preflight found the existing default AppProject is broad. It is not changed
  and no new privilege is granted. This is a trusted operator-owned fixed-source
  demo, not a new tenancy or untrusted Git execution boundary.
- All three pushes use explicit target ref, `-o ci.skip` and `[skip ci]` messages.
  Existing project Webhooks match main or a different exact test branch. No
  Jenkins job/build API, production main update or image operation is performed.

Execution: prepare baseline/update/revert commits locally in a disposable Git
repository with hooks and global/system configuration disabled. Verify exactly
one ConfigMap file and an identical baseline/revert tree. Push baseline through
the existing credential-bound Git transport; create only the Application through
the existing management connection. Argo alone creates/updates the ConfigMap.
Record revision, ConfigMap value/UID/resourceVersion and actual timestamps after
each sync. Push update, observe updated, push genuine git revert, observe baseline.
Stop on failure; do not force-push or edit the ConfigMap directly.

Rollback of the demo value: push the prepared revert commit (only this demo ref),
then wait for the exact revert revision and `baseline`. Do not reset Git history.
If setup must be removed: first verify the task-owned Application UID/source and
absence of finalizers; delete that Application without cascading, then verify
ConfigMap UID/namespace/name and delete only that ConfigMap. Delete only this
remote branch after confirming its expected head. Never delete Namespace,
production app, other resources or protected main. No cleanup deletion is needed
for successful delivery: keep the demo Application and baseline ConfigMap for
inspection and reuse.

Production acceptance: compare Deployment UID/generation/spec hash/image, Argo
spec and revision, Jenkins #270 and V1 Summary checksum, three Ready nodes,
PetClinic 3/3 and HTTP 200, Docker socket 0660. No production release/rollout.
