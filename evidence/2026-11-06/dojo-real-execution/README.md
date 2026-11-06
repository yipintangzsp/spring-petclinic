# Genuine controlled Semgrep → isolated DefectDojo delivery

User-authorized initialization: Product 7 `Security Manager V2 DEMO NON-PRODUCTION`; Engagement 4 `Semgrep Controlled Findings DEMO NON-PRODUCTION`; user 7 `security-manager-v2-demo`, no staff/superuser/groups/model permissions. Existing Product Type DevSecOps was reused unchanged. Product/Engagement 1 and 2 access returned 404 for the new account.

Existing REAL Artifact `web-042069ea-ae24-4f16-a914-4cbd8117aeaf` was reused; no new scanner or Policy evaluation. Existing Mapper/Router/HTTP Adapter created one Generic Findings Import Test 36 and two Findings 6628/6629. Source ERROR is retained in references; Dojo High is the unchanged governance mapping. Test branch_tag is the original Run ID and commit_hash is the original Result Digest (a provenance field, not a Git commit claim).

First POST returned 201. Exact query-back initially rejected the installed Dojo titlecase transformation. Read-only installed source inspection confirmed Finding.normalize_title calls titlecase. Only the two fixed-fixture expected titles are accepted in the explicit DEMO path; all rule/severity/location/reference/digest comparisons remain exact. Durable original SENT body digest + actual 201 + exact Test/Finding reconciliation allowed recovering an ACK without another POST. Default/mock paths retain strict original behavior.

Same-journal redelivery reused the verified ACK and made zero HTTP requests. Independent query verified one Test, two identical Finding IDs. This is local receipt/journal idempotency, not distributed exactly-once or native parser dedupe proof. No reimport or close-old action occurred.

Preexisting Product/Engagement/Test/Finding baselines are unchanged (including 6,627 original Findings). Token was in the Mac login Keychain; an owned temporary credential file required by the existing Adapter was removed in finally. Token was revoked at server and the exact Keychain item removed after verification. No administrator API Token was read. Account and demo records remain; human links require a legitimately authorized Dojo login.

Five targeted existing Adapter tests passed. UI/API and protected Finding URL routes verified; browser clicks NOT_TESTED. Production health verified after devops became reachable; no VM resource configuration changes, production configuration changes, release, rollout or Git push. Existing original evidence integrity remains FAILED; production Manager NOT_ACTIVE and runtime 14/16.

Rollback if requested: remove only the new DEMO account's membership/disable that account. Token already revoked. Preserve the DEMO Test/Findings as audit evidence unless explicit deletion requested. Revert this integration commit and restart only the local page after confirming no active run. Never remove Product 1/2, change production Findings, or rewrite historical evidence.
