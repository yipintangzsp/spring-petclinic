# Two independent provenance predicates

- `security-validation/v1`: existing #269 evidence that a CI security validation ran against a Candidate. It does not claim to have built that image.
- `image-build/v1`: new optional evidence emitted around actual Maven compilation and dual-architecture Buildx execution. Never backfill this for an existing Candidate.

## Producer

Use `Jenkinsfile.candidate-build` from a fixed private GitLab commit. This artifact-only job has no deploy, GitOps, Argo CD or business-write stage. It keeps the original disk/memory admission and heavy Lease. Tags use a separate numeric range and existing tags are rejected. The output identity is the immutable OCI index digest, not the tag.

`build-record.mjs package` records clean source identity, builder, timestamps and the JAR checksum around real Maven execution. `image` verifies that receipt, records the exact Dockerfile/JAR/offline-package context, builds both platforms with native BuildKit min provenance, checks the resulting registry index and emits `build-provenance.json`. Harbor copy preserves the index digest. `build-attestation.mjs create` signs and immediately verifies an independent in-toto statement with the existing Cosign key; private temporary files are removed in finally.

## Consumer

Security Manager accepts `buildProvenance: [enabled:true,image:<fixed digest>,commit:<build source commit>,repository:<build repository>,builder:<producer Jenkins job URL>,buildNumber:<producer build>]`. `securityBuildProvenance` verifies the signature, subject and explicit expected build identity. Enforce blocks on mismatch; audit warns; disabled/off returns before credentials or stages.

The read-only audit entry offers `ENABLE_IMAGE_BUILD_PROVENANCE` (default false) and `BUILD_PROVENANCE_EXPECTATION` (JSON with exactly commit/repository/builder/buildNumber). Use the producer identity, not the later audit job identity. No automatic production promotion is added. Existing #260/#269 gate semantics remain unchanged when disabled.

Reports: `.devsecops/build-compilation.json`, `build-provenance.json`, `build-attestation-envelope.json`, `build-attestation-verification.json`, `build-provenance-status.json`; Buildx metadata is archived separately. Additive summary fields flow through the existing Loki publisher. No fabricated DefectDojo finding.

## Trust and limitations

This is a custom image-build predicate, not SLSA certification. The current Jenkins administrator, signing credential and Docker daemon remain trusted. Maven dependency resolution is not hermetic; resolved dependency checksums are not claimed complete. Local context and final JAR are hashed; native BuildKit provenance supplies image-build material details. Build arguments never contain secrets. Signing uses the existing private-registry, no-transparency-log policy; that limitation remains explicit.

## Verification status (2026-10-30)

Local contract/cryptographic positive and negative tests: 14 PASS. Both Jenkinsfiles pass the Jenkins native model validator.

Actual producer `petclinic-candidate-build #2` SUCCESS; full read-only consumer `petclinic-ci #270` SUCCESS, source `9a78cc89f22fa98fb1ffcc43e2ae279299471793`. Candidate: `core.harbor.domain/petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55`. The compilation receipt, 81 input-file checksums, both native BuildKit platform provenance entries and immutable index digest were archived. Real signed-envelope checks rejected changed digest, source, builder and tampered payload. Trivy C/H/M/L: 0/0/108/8; existing WARN semantics unchanged. DefectDojo/Kubescape and original Grafana metrics remained available.

The existing overview adds an independent Image Build Provenance / Attestation panel. `security-summary.json` and Loki record both proof types separately. Production remains digest `489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137`, 3/3 Ready and HTTP 200; GitOps revision unchanged, promotion stages not executed, Lease released and Jenkins quiet=false.

Producer #1 failed before signing: the host had reverted to QEMU 8.2.2 and crashed during amd64 libc6 unpack. The already-verified QEMU 10.2.3 binary was re-registered without restarting VM/K3s/containers; #2 then succeeded. No new boot service was installed; recheck binfmt after future reboot. This is a host prerequisite, not an exception to any security gate.

References: https://docs.docker.com/build/metadata/attestations/slsa-provenance/ and https://slsa.dev/spec/v1.0/provenance
