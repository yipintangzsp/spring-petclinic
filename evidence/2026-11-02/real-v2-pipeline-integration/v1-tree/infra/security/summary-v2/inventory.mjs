// Matches the approved 18-label inventory: one alias and one post-approval source.
export const EXPECTED_SOURCES = Object.freeze([
  'sbom','regression','falco-baseline','kyverno','kubescape','gitleaks','sops',
  'trivy','cosign','sonarqube','zap','falco-final','defectdojo','provenance',
  'build-provenance','semgrep-command-audit'
]);
export const ALIASES = Object.freeze({semgrep:'semgrep-command-audit'});
export const POST_APPROVAL_SOURCES = Object.freeze(['security-approval-promotion']);
