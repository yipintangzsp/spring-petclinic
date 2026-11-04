# Security Manager V2 Candidate implementation — incomplete integration

Implemented runnable candidate code; production remains inactive. Baseline HEAD:
`c371caa`, branch `fix/security-manager-plugin-switches`. No push, scanner execution,
DB refresh, image signing, Jenkins build/job creation, release, GitOps mutation or
rollout occurred. Existing five user-modified documents were left alone. A clean staged-tree checkout also passes all 45 Candidate tests, proving the reused dependency closure is included.

The precise verdict is in [acceptance.json](acceptance.json). Passing tests of error
handling do not remove the following two integration gaps.

## Blockers retained, not bypassed

1. **Gitleaks frozen source mismatch.** Frozen manifest expects
   `Jenkinsfile.security-audit` SHA
   `e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2`;
   current source is
   `6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c`.
   Both archived Gitleaks inputs correctly return POLICY_ERROR through the existing
   engine. Initial 7/9 differential log is retained in
   `stage-d-initial-frozen-blocker.tap`. Later tests check the error is preserved,
   not that Gitleaks compatibility passed. Semgrep/Cosign each match their old
   PASS/FAIL decisions. No frozen manifest/source was rewritten or restored over
   current code. Affected Gitleaks compatibility validation stops here.
2. **Full real historical payload unavailable.** Existing actual Runtime receipts
   explicitly say `rawPayloadPersisted=false`. A digest/receipt cannot reconstruct
   the original facts. The executable first-batch packets are archived **controlled
   compatibility** inputs from the previous frozen tests. Their raw facts are copied
   unchanged, tied to original hashes and always labeled `ARCHIVED_CONTROLLED_REPLAY`.
   They are not represented as fresh scans, full real historical production inputs,
   production incidents or Runtime proof. Accordingly independent real/historical
   plugin integration is INCOMPLETE, although its offline runner contract passed.

The only next permitted work is a separately scoped Gitleaks versioned source
compatibility review and read-only search for an existing full raw archive. Do not
weaken a lock, start Trivy/Dojo, connect production Summary V2 or expand permissions.

## Implemented stages

| Stage | Implementation and evidence | Result |
|---|---|---|
| A | strict config/default standard; all 5 profiles; global/profile/component/project precedence and origin; 3 version pins | VERIFIED candidate |
| B | 13 static plugin contracts; unknown/duplicate ID rejection; removal/defaults tested; Dojo kept as consumer | VERIFIED candidate |
| C | scoped missing/unavailable/profile/platform states; Trivy preflight-only even with asserted capabilities | VERIFIED candidate |
| D | bounded independent Node Workers, empty env/execArgv, timeout/cancel/join, SHA-approved archive collection | offline contract VERIFIED; real historical criterion INCOMPLETE |
| E | execution status separate from decision; nonexecution never PASS; audit preserves FAIL; all promotions blocked | VERIFIED candidate |
| F | reuse unchanged existing engine; claim before await; one evaluation; exact same result object/digest for Gate/Summary | owner contract VERIFIED; Gitleaks integration INCOMPLETE |
| G | exclusive private directory, exact raw bytes, input/config/context/fact/result hashes, read-only files, pinned seal verification | VERIFIED candidate, not privileged-host WORM |
| H | independent `candidate-summary.json`, all registered results and blockers; no V1 writer change | VERIFIED candidate |
| I | independent fixed dry-run/local evidence contracts, verified receipts, failed delivery block; Dojo future contract not live | VERIFIED candidate |
| J | java-web/python-api/container-service offline CLI and library smoke; per-project policy and capability differences | VERIFIED offline |

Policy `baseline-v2` is explicitly an identical candidate compatibility alias of the
existing baseline-v1 rules, not a new production rule set. `strict-v1` pins the
existing strict level. No frozen baseline hash or FAIL floor changed. Full raw
facts remain separate; safe engine metadata projection follows the existing owner.
Caller-declared capabilities are labeled as such, not fresh infrastructure proofs.
No new production Jenkins job was safe/needed; a standalone local CLI was delivered.

## Tests and actual observations

- Final Candidate: **45 PASS / 0 FAIL / 0 SKIP** in `candidate-tests-authoritative.tap`.
  Earlier development failures are retained with their original names.
- CLI runs: `java-two` PASS; `python-strict` PASS; `master-off` DISABLED;
  `trivy-blocked` INCOMPLETE; `audit-fail` FAIL with candidate build allowed;
  `gitleaks-blocker` POLICY_ERROR with exit 1. All promotion statuses BLOCKED.
- Old/new Trivy **190/190 each**, **184 unchanged differential samples per version**.
- Helm Shadow 43/43; source lock 54/54; Policy Core 5/5; Contract 10/10.
- All compatibility tests ran in fresh temporary copies with evidence writes limited
  to this new output. No old frozen evidence/manifest was regenerated in place.
- Evidence retention check: **9509 previous source/evidence files unchanged**.
  Original historical evidence integrity remains **FAILED**, as before.
- Catalogue contains only pinned prior controlled fixtures. No production Secret,
  private key or environment export was taken. Production checks use metadata and
  selected state fields. Synthetic Cosign placeholders are explicit test data.

## Production verification and timing

Initial preflight captured Jenkins/Argo/deployment/HTTP/V1 and Trivy metadata before
candidate implementation. The detailed Docker/node snapshot pair was collected
later during development and after integration, not before the first local unit
fixture. These distinct timestamps are preserved rather than relabeled.

Final read-only checks prove Jenkins #270 SUCCESS; V1 hash
`ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8` unchanged;
Argo Synced/Healthy with same revision/spec/UID; 3 nodes Ready; PetClinic 3/3 with
3 Ready Endpoints and HTTP 200; production digest unchanged. Docker socket remains
root:988 **0660**, same inode 1405; daemon PID/start/NRestarts unchanged (restart
count for this task **0**). All 13 Docker container identities, start/restart and
health status unchanged, including existing DefectDojo containers. Rotating health
probe log timestamps are deliberately not treated as deployment changes.

Trivy DB/cache file size/inode/mtime and metadata hashes are unchanged. No refresh
or scan ran. Available guest disk increased from ~41.96 to ~42.16 GiB through normal
background activity; the 45.78 GiB floor and independent capacity blockers remain.

Runtime remains **14/16**. REAL_POLICY_OWNER, REAL_RUNTIME_FACT_CAPTURE,
IMMUTABLE_ARTIFACT_RUNTIME, Trivy/Dojo Runtime and SUMMARY_V2_MIGRATION remain INCOMPLETE.
Production Security Manager remains NOT_ACTIVE. Release=0, rollout=0, push=0.

## Code, dependencies and rollback

New executable code and examples live in `infra/security/manager-v2/`. See its README
for CLI, APIs, constraints and rollback. Existing untracked authoritative Policy
engine/adapter dependencies are added to the local commit unchanged so a clean
checkout can import them; `reused-dependencies.json` records their origin and hashes.
This tracks existing code, not edits or activation of those other sources.

No production rollback is needed: stop using the candidate CLI and preserve output
seals. If reverting the local candidate commit, retain evidence and avoid unrelated
user changes. Read-only files plus hashes detect tampering; root/owner chmod remains
possible, so this candidate is not claimed as canonical production immutable storage.

STOP. No next production phase is authorized by this report.
