# DevOps learning labs

This directory extends the existing private platform with independently managed learning exercises. It does not replace the Petclinic ingress, database, CI, or observability services.

## First exercise: certificate lifecycle

- `cert-manager/`: official cert-manager v1.21.2 chart, SHA256 checked against the official Helm index, rendered with `values.json` for Kubernetes 1.36.1. The upstream signature has not been verified. `upstream-lock.json` records the source and rendered digest. The upstream chart is Apache-2.0 licensed.
- `applications/`: two bootstrap Argo Applications. Apply these only after the containing source revision passes the existing private Jenkins release. They intentionally live outside `k8s/production` to avoid automatic installation before that gate.
- `tls/`: a namespace-scoped learning CA, one server certificate and a small existing pinned nginx image behind Traefik. No CA or server private keys are stored in Git.

The three cert-manager controllers request 200m CPU and 320Mi memory in total; limits total 1500m CPU and 640Mi. Startup check adds 10m/32Mi requests and 100m/64Mi limits temporarily. The lab web requests 25m/24Mi and is capped at 100m/64Mi. This is a single-replica learning installation, not an HA claim. No persistent volume is created by this exercise.

The lab namespace has an explicit ResourceQuota and LimitRange. Do not reuse it for production workloads or add expensive labs without re-budgeting. Controllers remain running for certificate lifecycle management; the web Deployment can be set to zero through Git when not studying. Scaling cert-manager to zero while leaving its admission webhook registered is not a supported shutdown procedure.

## Acceptance and use

The learning endpoint is `https://tls-lab.devops.local`. It uses an internal learning CA, not a publicly trusted ACME certificate. No system or browser trust store is changed automatically.

Read the public CA certificate without exporting the private key:

```sh
ssh 192.168.1.58 'sudo kubectl -n devops-lab get secret lab-root-ca -o jsonpath="{.data.tls\.crt}"' | base64 -d > /tmp/petclinic-lab-ca.crt
curl --noproxy '*' --cacert /tmp/petclinic-lab-ca.crt \
  --resolve tls-lab.devops.local:443:192.168.1.58 https://tls-lab.devops.local/
```

Renew only the leaf certificate with a checksum-verified cmctl CLI (`cmctl renew tls-lab -n devops-lab` using the existing kubeconfig). Verify Certificate revision increases, serial and public key fingerprint change, Traefik serves the new certificate, and CA-verified HTTPS still succeeds. Do not delete the Secret to request renewal. Automatic renewal scheduling must also have a real `status.renewalTime`; an immediate manual renewal is not evidence that the scheduled renewal time has already occurred.

Inspect Certificate/CertificateRequest/Issuer status and Events, the three cert-manager Deployment logs, Argo Applications and Prometheus ServiceMonitor targets. Do not print Secret objects or private keys in logs or reports.

## Publication and removal

Submit source to private GitLab only. Use the existing full Jenkins checks once for this functional addition; documentation-only follow-ups must carry both `[skip ci] [ci-skip]`. Bootstrap `platform-cert-manager` first, wait for its webhook and API check, then bootstrap `devops-tls-lab`.

Normal configuration rollback is a private Git revert. Pruning is disabled to protect generated CA/leaf Secrets and cluster-scoped CRDs. Removing cert-manager requires the upstream ordered uninstall procedure; never remove its CRDs as a casual rollback. Deleting a namespace deletes its generated keys, so any data deletion still requires the user's separate approval.

Upstream references: https://cert-manager.io/docs/releases/ ; https://cert-manager.io/docs/usage/certificate/ ; https://cert-manager.io/docs/installation/best-practice/
