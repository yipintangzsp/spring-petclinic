# Security Manager Capability Matrix · 2026-11-01

Current local source contract and inherited 2026-10-29/30 evidence; no new scans, live queries or deployments

VERIFIED is limited to notes/evidence. FAILED denotes requested architecture not met. Profile enable is static review; generic runtime verification is listed separately. NOT_TESTED is never pass. PetClinic dependency VERIFIED means independence demonstrated; otherwise not established. Final result evaluates full requested contract, not existing scanner health. Historical adapter checks do not transfer to generic columns.

完整字段与证据索引：`capability-matrix.json`、`evidence-index.json`。本表不代表当前集群实时健康；没有重新运行旧插件。

| Capability | gitleaks | semgrep | sonarqube | sbom | trivy | cosign | kubescape |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Enabled by default | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED |
| Independent disable | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Required capabilities | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED | VERIFIED |
| Missing capability behavior | FAILED | FAILED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | VERIFIED |
| Raw report | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Normalized result | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Default Security Level | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Security Level support | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Profile support | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Component override | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Project override | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Policy version | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Policy evaluation | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Summary integration | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Gate integration | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| DefectDojo integration | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_APPLICABLE | NOT_TESTED | NOT_APPLICABLE | NOT_TESTED |
| Loki/Grafana integration | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Audit behavior | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Enforce behavior | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Standalone test | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Integration test | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| PetClinic dependency | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Final result | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |

| Capability | zap | defectdojo | provenance | build-provenance | sops-age | kyverno | falco |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Enabled by default | VERIFIED | VERIFIED | FAILED | FAILED | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| Independent disable | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| Required capabilities | VERIFIED | VERIFIED | NOT_TESTED | NOT_TESTED | FAILED | FAILED | FAILED |
| Missing capability behavior | NOT_TESTED | VERIFIED | FAILED | FAILED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Raw report | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Normalized result | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Default Security Level | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Security Level support | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Profile support | NOT_TESTED | NOT_TESTED | FAILED | FAILED | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| Component override | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Project override | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Policy version | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Policy evaluation | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |
| Summary integration | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Gate integration | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| DefectDojo integration | NOT_TESTED | VERIFIED | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| Loki/Grafana integration | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Audit behavior | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Enforce behavior | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Standalone test | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Integration test | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| PetClinic dependency | NOT_TESTED | VERIFIED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Final result | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED | FAILED |

## Scope notes

- **gitleaks**: source checkout; sourceRoot assumed ready; git archive HEAD; inherited #3/#5/#7; no zero-findings full-chain proof for every policy level
- **semgrep**: source checkout; #6 isolated scanner + Dojo Test35 Finding1 + stable reimport IDs; #7 confirmed Java violation blocks; no configurable policy engine
- **sonarqube**: sonarProject, sonarCommand, token, URL; adapter #270 verified; generic portability not tested
- **sbom**: existing CycloneDX sbomFile; report validation not SBOM generation in generic path
- **trivy**: fixed Harbor digest + registry credential; adapter #270 verified; generic Harbor endpoint hardcoded; C/H blocking inline
- **cosign**: fixed digest + source public key + toolchain; adapter #270 verified; common native report contract absent
- **kubescape**: yamlPath + pinned local tool/artifacts; generic smoke missing config recorded; cluster/YAML governance verified only in adapter #270
- **zap**: bounded readOnlyUrls + scanner runtime; passive findings blocking=0 inline; adapter #270 verified
- **defectdojo**: dojoEngagement + token + successful reports/build/source of preceding enabled scanners; current(id) depends on private files and scheduling order; router is currently a plugin
- **provenance**: candidate digest + source identity + signing/registry credentials; extra opt-in, fixed credential IDs; two predicate types remain separate; #269/#270 evidence retained
- **build-provenance**: enabled=true + image/commit/repository/builder/buildNumber + registry access; extra opt-in; producer#2 and consumer#270 verified historically
- **sops-age**: adapter-only encrypted signing credentials checks; absent from generic profile registry, not safe to mark as independently controllable plugin
- **kyverno**: existing live admission policy/platform checks; adapter-only; no fabricated Dojo vulnerability
- **falco**: existing runtime sensor/platform checks; adapter-only; no fabricated Dojo vulnerability
