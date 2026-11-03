# FUTURE ONLY — no cutover authorized

STOP until the canonical security/runtime roadmap is satisfied. Trivy remains environment blocked, Dojo transitively blocked, wired capability14/16; Summary V2 remains incomplete. Helm shadow success cannot change those statuses. The previous resource audit stays closed until material resource change; this runbook does not reopen it.

1. Obtain separate cutover approval and satisfy runtime/security roadmap prerequisites, including actual signed approved digest and full Gate evidence. Revalidate current source baseline; never promote from a candidate-only digest.
2. Freeze Argo Application spec, live resource UIDs/selectors/desired state, GitOps revision, image, EndpointSlices, HTTP, metrics/logs/traces and rollback references. Verify backup/data safety and one reconciliation owner.
3. Re-run chart lint, schema checks, semantic equivalence against **current** GitOps revision, real supported policy checks, and approved non-mutating dry-run/diff. The Phase1 baseline must not be assumed current forever.
4. Resolve the old directory's platform-alertmanager, spark-operator and Harbor alias resources into explicitly preserved V1 ownership before any source switch. Keep the plain manifests available for rollback. No double Application ownership of PetClinic names.
5. Review the inactive candidate's source parameters; change the existing authoritative Application's source through its Git-managed definition during the approved window. Do not apply the differently named candidate Application as another controller. Preserve destination/revision policy/selectors and do not introduce Helm release adoption metadata.
6. Let Argo CD alone render/reconcile the chart. Jenkins writes reviewed GitOps changes only. No direct Helm deployment, kubectl workload mutation, resource recreation or second controller.
7. Verify same object identities and selectors, rollout safety/PDB, desired Ready replicas, immutable approved image, Service endpoints and continuous HTTP. Validate Prometheus targets, Grafana panels, Loki/Alloy labels/logs and Jaeger tracing. Record failures/minimum availability rather than claiming zero impact from Ready alone.
8. STOP on selector/resource ownership collision, unapproved digest, semantic drift, missing policy evidence, DB initialization change, extra Secret values, lost monitoring/tracing, degraded Ready/endpoints/HTTP or unexpected platform-resource removal.
9. Roll back by Git revert to the last approved digest/config and, if needed, restore the V1 source definition in Git. Argo performs convergence. Verify restored UIDs/selectors/health/HTTP/metrics/logs/traces. A Git revert is only verified after convergence; a Helm CLI rollback is not the authoritative recovery path.

No step above has been executed by Phase1. The current Argo source remains `k8s/production`; the chart and candidate definition are inactive representations.
