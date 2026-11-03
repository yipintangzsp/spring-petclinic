# Helm Phase 1 — inactive shadow pipeline

Production stays on the existing plain-manifest GitOps path. Helm does not deploy anything in Phase 1. `HELM_ENABLED=false` is the default; the original pipeline text, including every security stage and promotion guard, is byte-identical after removing the explicitly marked additive Helm blocks.

`HELM_ENABLED=true` is validation-only and requires `PROMOTION_ACTION=audit-only`. The production pipeline evaluates the existing Security Manager first; a failed existing Gate cannot be bypassed to reach Helm. A separate `Jenkinsfile.helm-shadow` job validates the **already deployed configuration**, without re-running or claiming success for the incomplete security runtime. Its off-mode run exercises the disabled helper and pipeline compatibility tests. It is not a complete new execution of the production security pipeline; production build #270 is intentionally unchanged.

Stages: Helm Validation Preparation → Helm Lint → Helm Render → Rendered Manifest Validation → Helm Policy Validation → GitOps Candidate Validation. The shadow job archives `.helm-shadow/**`. It never writes Security Manager summaries or registers a plugin. Helm deployment representation is separate from Security Summary V2; security runtime stays14/16.

## Baseline and ownership

Baseline: GitLab `root/petclinic-platform`, `main`, revision `340ef4b8c74e3c2a5820da8d98b0f134283bb8d9`. The active Argo Application owns `k8s/production`. The local checkout contains an older plain-manifest image and is **not** the baseline for this comparison.

The chart preserves11 PetClinic resources: Deployment, Service, Ingress, primary ConfigMap, PDB, four Grafana ConfigMaps, ServiceMonitor and PrometheusRule. Pod selector remains exactly `app: petclinic`; default ServiceAccount is retained with token automount false. No app-owned ServiceAccount/RBAC exists to migrate. PostgreSQL and pull credentials remain external Secret references; optional platform-snapshot ConfigMap remains an external prerequisite. No Secret values are rendered.

Two platform Applications and the Harbor alias Ingress are outside this chart. They stay on V1. A future source switch must first resolve ownership of these three resources and prevent prune/removal or accidental takeover. The candidate Application file is NOT_ACTIVE/VALIDATION_ONLY, including an inherited automated sync policy: **never apply it as a second controller alongside V1**.

## Tooling and rendering

Helm is pinned to3.22.1 using the [official immutable release/checksums](https://github.com/helm/helm/releases/tag/v3.22.1). ARM64/AMD64 Linux and local Darwin ARM64 archives and extracted binaries have explicit SHA256 pins. Tools are workspace-local under `.tools`, not a host-global install; a cache hash mismatch fails closed. Helm3 security support ends2027-02-10 per [Helm lifecycle](https://helm.sh/blog/helm-v3-end-of-life/); revisit this lock before then. No Tiller.

Templates emit JSON documents, a strict YAML subset, into `rendered.yaml`. This permits deterministic JSON parsing with existing Node tooling on Jenkins (no Python/PyYAML installed there), and avoids adding another YAML parser dependency. The Helm CLI still parses values/chart YAML normally. Object-key order/document formatting are the only normalized differences. Arrays, unknown fields, selectors, annotations, probes, data strings and all runtime fields compare exactly. `infra/helm/baseline/current-desired.json` is an immutable comparison fixture, **not** approval for a new image.

Existing admission code uses server dry-run; the Kubescape runner acquires/mints validation identity and needs the existing Lease. Phase1 does not invoke either live path or alter them. Additional frozen security-field preservation checks reject privileged/root/host access drift, but are not a Kyverno engine or a Kubescape scan. `HELM_POLICY_STATUS=NOT_APPLICABLE` records this limitation; preserved-security checks are separately PASS. No new security source is counted.

## Digest trust and future updater

`image.repository@image.digest` is authoritative. `appVersion` is metadata only. Candidate digest alone cannot update production Helm values. Future CLI `infra/helm/update-image-digest.mjs` requires the frozen Cosign tool checksum, signed `approved-release.json`, signature verification with existing repository public key, existing promotion contract identity checks, and a matching previous-runtime digest. It writes a **new candidate output** only, never the input file or Git remote. Tests of the pure transformation use explicitly synthetic approval fixtures; they are not real approval evidence.

Future pipeline: candidate → existing Security Gate → signed Approved Digest → candidate values file → lint/render/policy/equivalence review → separately authorized GitOps commit. Commit model: `deploy(petclinic): <approved-digest-short>`. There is no enabled commit/push route in shadow mode.

## Reproduce offline validation

```sh
node infra/helm/tool.mjs
node --test infra/helm/chart.test.mjs infra/helm/pipeline-contract.test.mjs
node infra/helm/pipeline.mjs prepare
node infra/helm/pipeline.mjs lint
node infra/helm/pipeline.mjs render
node infra/helm/pipeline.mjs validate
node infra/helm/pipeline.mjs policy
node infra/helm/pipeline.mjs candidate
```

These commands render/validate only. No cluster credential is required. Supply only checksum-pinned archives to the workspace cache when external downloads are unreliable. Never replace the pinned release with `latest` or a system Helm4 binary.
