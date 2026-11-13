# Generic plugin switches

- `disabledModules: ['semgrep']` disables selected modules.
- `moduleEnabled: [gitleaks:false, semgrep:true]` is the equivalent explicit boolean map. `disabledModules` wins conflicts; global mode=off wins all switches. Unknown IDs/nonboolean values fail before execution.
- A switch selects eligibility inside the chosen Profile; it does not fabricate missing inputs or automatically enable optional provenance. Disabled modules emit `status=skipped`, `displayStatus=SKIPPED`, `reason=DISABLED`, with no credentials or scanner execution.
- Known IDs: gitleaks, semgrep, sonarqube, sbom, trivy, cosign, kubescape, zap, defectdojo, provenance, build-provenance.
- Enabled modules lacking required configuration remain `not_configured`. Cosign requires both the image and public key.
- `enabledModules` sent to DefectDojo contains only scanners actually scheduled. Summary ignores prior files belonging to disabled/not-configured modules; Loki receives explicit skipped records.
- The frozen PetClinic adapter rejects attempts to disable its gates; default behavior and release code are unchanged. Generic audit and enforce keep existing finding/operational-failure semantics.
