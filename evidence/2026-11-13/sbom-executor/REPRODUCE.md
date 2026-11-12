# W9 SBOM executor image mode - reproduce

Verdict: BLOCKED at the frozen Policy contract (see verification.json, gap G-SBOM1). No source files were modified.

## Probe (adapter rejection, both architectures)

From the repository root (Node on PATH):

    node evidence/2026-11-13/sbom-executor/probe-adapter.mjs

Expected output: raw/probe-output.json - genuine step1 image SBOMs FAIL at
sbomEvidence / sbomParent / engine with reason "Nonempty CycloneDX 1.6
dependency inventory required" (failurePhase=validation); probe copies with
only specVersion rewritten to 1.6 PASS, isolating the single blocking check.

## Untouched-surface check

    sha256sum -c evidence/2026-11-13/sbom-executor/protected-before/sha256-before.txt

All listed frozen Policy files, the SBOM executor, the registry and Core must
verify OK (they were never edited by this line).

## Regression commands

    node --test infra/security/manager-v2/*.test.mjs
    node --test infra/security/*.test.mjs infra/observability/*.test.mjs
    node --test --test-reporter=tap infra/security/manager-v2/consumers/*.test.mjs

Observed 2026-11-13: 176/176, 147/147, consumers 114 pass / 48 fail (baseline class).
