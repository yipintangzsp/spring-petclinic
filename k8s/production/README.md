# Petclinic Production Kubernetes Baseline

This directory contains the declarative production baseline for the Petclinic application.

## Managed in this directory

- `petclinic.yaml`
  - Deployment
  - Service
  - Ingress
- `petclinic-configmap.yaml`
  - Non-sensitive application configuration
- `postgresql-service.yaml`
  - Network dependency used by Petclinic to reach the shared PostgreSQL instance

## External / shared dependencies

The following resources are intentionally not managed as part of the Petclinic application baseline:

- PostgreSQL Deployment in namespace `ns-data`
- PostgreSQL PVC
- PostgreSQL administrator Secret
- Petclinic PostgreSQL database
- Petclinic PostgreSQL role
- `petclinic-db` Secret values

Petclinic currently expects the following database endpoint:

`postgresql.ns-data.svc.cluster.local:5432/petclinic`

The application expects Secret `petclinic-db` in namespace `petclinic` with these keys:

- `POSTGRES_USER`
- `POSTGRES_PASS`

Secret values must not be committed to Git.

## Database bootstrap boundary

The shared PostgreSQL instance currently contains:

- database: `petclinic`
- role: `petclinic`

Creation and credential management for this database and role are currently bootstrap/external operations and are not yet managed by this application GitOps baseline.

## Deployment image

The image declared in `petclinic.yaml` represents the current production baseline.

Future GitOps stages will move release promotion toward:

CI builds image -> Git image reference update -> ArgoCD sync -> Kubernetes

instead of Jenkins directly mutating the live Deployment.

## Jenkins to ArgoCD handoff

Current transitional deployment flow:

`Jenkins CI -> build image -> update Git image reference -> push main -> Jenkins direct kubectl deploy`

This transitional mode remains in place until ArgoCD is installed, configured, and verified.

Target GitOps deployment flow:

`Jenkins CI -> build image -> update Git image reference -> push main -> ArgoCD sync -> Kubernetes`

After ArgoCD takes ownership of `k8s/production/`, Jenkins must stop directly mutating the Petclinic Deployment.

The Jenkins `Deploy to Kubernetes` stage and its direct `kubectl patch` release logic must be removed or disabled at cutover. Jenkins and ArgoCD must not act as concurrent deployment controllers for the same Deployment.

## ArgoCD cutover conditions

ArgoCD may become the production deployment controller only after all of the following conditions are met:

1. The ArgoCD Application is configured to track the intended repository, branch, and `k8s/production/` path.
2. The ArgoCD Application reports the expected production resources and reaches a healthy synchronized state.
3. Git desired state matches the currently validated live production state before control is transferred.
4. Jenkins Git image promotion is verified to update the production manifest successfully.
5. Jenkins direct Deployment mutation is disabled or removed as part of the cutover.
6. A Git-based rollback procedure is validated before the Jenkins revision-based rollback path is retired.

## Rollback ownership after cutover

Before ArgoCD cutover, Jenkins retains the existing Kubernetes revision-based rollback behavior.

After ArgoCD cutover, the intended rollback control path is:

`Git revert or previous known-good manifest -> push -> ArgoCD sync -> Kubernetes`

Kubernetes Deployment revisions may still provide diagnostic history, but Git becomes the authoritative production release history.
