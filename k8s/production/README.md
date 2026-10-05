# Petclinic Production Kubernetes Baseline

This directory contains the declarative production baseline for the Petclinic application.

## Managed in this directory

- `petclinic.yaml`
  - Deployment
  - Service
  - Ingress
- `petclinic-configmap.yaml`
  - Non-sensitive application configuration
- `petclinic-pdb.yaml`
  - Requires two available replicas for voluntary eviction; does not provide cross-node HA
- ServiceMonitor, PrometheusRule and three existing Grafana dashboard ConfigMaps
  - The existing `petclinic-app-metrics` UID now contains the consolidated troubleshooting dashboard

## External / shared dependencies

The following resources are intentionally not managed as part of the Petclinic application baseline:

- PostgreSQL Deployment in namespace `ns-data`
- PostgreSQL Service (reference manifest in `../shared/`, outside this application's sync directory)
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

The active release promotion flow is:

CI builds image -> Git image reference update -> ArgoCD sync -> Kubernetes

instead of Jenkins directly mutating the live Deployment.

## Current Jenkins to ArgoCD handoff

Verified on 2026-09-30: `Jenkins CI -> multi-architecture registry image -> Git image and release metadata promotion -> ArgoCD sync -> Kubernetes`.

Jenkins waits for the promoted Git revision, ArgoCD Synced/Healthy, and the expected live image. It does not directly mutate the deployment. Git is the rollback authority; restore the previous production manifest and push a normal commit for ArgoCD to reconcile.

## Continuing the current task

The baseline audit, workflow upgrades, validation progress, release evidence and rollback procedure are recorded in [2026-09-30 upgrade task](../../docs/UPGRADE-20260930.md). Update that ledger when continuing this work.

The current [2026-10-05 audit and validation](../../docs/UPGRADE-20261005.md) documents production endpoint boundaries, explicit shutdown budget, PDB and the existing dashboard upgrade. Use the [fault and rollback runbook](../../docs/FAULT-DRILLS.md) for scoped diagnosis. Current placement remains on devops; do not drain it or enable HPA without shared-capacity and worker-network acceptance.
