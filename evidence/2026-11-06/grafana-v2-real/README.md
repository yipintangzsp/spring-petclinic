Grafana V2 delivery — 2026-11-06

- Independent Folder: `security-manager-v2`; Dashboard UID: `security-manager-v2-candidate`. Original dashboards were not overwritten.
- Service Account: `security-manager-v2-dashboard` (ID 2), basic role Viewer. Folder edit only; outside-folder dashboard creation actually returned 403. No global Admin.
- Viewer inherits the existing read/query access to all datasources. This is not a Loki-only token; no datasource ACL/global permission was changed.
- Credential reference: macOS Login Keychain, service `petclinic-security-manager-v2-grafana`, account `security-manager-v2-dashboard`. Token ID 1, lifetime 86400 seconds. No token is in this directory, page, or repository. Do not print it for routine checks.
- Imported existing eight-panel Candidate. Fixed historical window preserves the actual Semgrep execution time. Five query panels contain data; availability/delivery panels 4 and 5 have No data; panel 8 is a static notice. No new scan this round.
- Grafana requires normal login for a human browser. Service Account authentication was used to verify Dashboard API, scoped creation, and actual Loki datasource queries. Browser clicks were not tested.
- Page: `http://security.devops.local:17862/#candidate-overview`. Managed local page restart: `node infra/security/manager-v2/view/control.mjs restart`.

Rollback, if requested: using the existing Grafana management UI, revoke token ID 1 (or delete Service Account ID 2), delete only Dashboard UID `security-manager-v2-candidate`, then delete only Folder UID `security-manager-v2` after confirming it contains no other resources. Remove the exact Keychain service/account entry above using Keychain Access. Revert only this task's view patch if needed. No Docker/Kubernetes/service restart is needed. Rollback was prepared, not executed.

Production health is a point-in-time read-only check in `production-health.json`; V1 Summary and production Jenkins job hashes still match the existing baseline, as recorded in `verdict.json`. Production Security Manager remains NOT_ACTIVE; runtime remains 14/16; release=0, rollout=0; original evidence integrity remains FAILED.
