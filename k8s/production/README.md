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
