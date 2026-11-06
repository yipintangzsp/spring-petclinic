# DefectDojo DEMO authorization request — not executed

Current HEAD 51b9362d. Only admin and jenkins-petclinic exist. The non-admin identity is authorized for shared Products 1/2; Engagements 1/2 belong to those shared contexts. The earlier disposable runtime identity/product/token were cleaned up. No credential value was read this round.

Request one limited initialization through the existing authorized host-local DefectDojo management entry (`sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell ...`):

1. Create Product `Security Manager V2 DEMO NON-PRODUCTION`, using an existing non-production Product Type (validate the actual ID before creation; never change existing types/products). Create Engagement `Semgrep Controlled Findings DEMO NON-PRODUCTION` in that Product.
2. Create `security-manager-v2-demo`: active, nonstaff, nonsuperuser, unusable password, no groups/model permissions. Authorize it for only the new Product. No memberships in Products 1/2.
3. Create one API Token for this identity. Keep it exclusively in the existing Mac login Keychain (`service=petclinic-security-manager-v2-defectdojo`, `account=security-manager-v2-demo`) and transient process memory. No admin Token retrieval or export. Use the new identity for real context verification and import only. Prove Products 1/2 inaccessible before mutation.

Before any initialization, reject conflicting existing names and take a read-only baseline of existing governance objects. Keep the created IDs in an independent nonsecret ledger. No creation, grant, token or Product/Engagement write is authorized/executed by this document.

After approval: reuse the existing Router, mapper, HTTP adapter and append-only delivery journal with a fixed new real-target opt-in. Its default/mock paths stay unchanged. Bind numeric target IDs, names, project java-fixture and profile java-web; reject Product/Engagement 1 and arbitrary targets. Import only the prepared genuine artifact. Verify returned Test/Finding records and exact mapping; never reimport/close old findings. Preserve the original ERROR source severity separately from the existing Dojo High governance mapping. Verify duplicate delivery via the existing journal without a second import mutation.

Artifact: `web-042069ea-ae24-4f16-a914-4cbd8117aeaf`, result digest `a61aead230295688c2070bcce50ac32eacd6c6a0858f581d44074e49f1c35e19`, Policy FAIL, one prior Policy evaluation. Existing Consumer prepared two findings: java-runtime-exec and java-weak-cipher. No new scan is needed.

Rollback/revocation: revoke only the newly created account Token and exact Keychain item; remove only the newly created Product membership. If the new context has no Test/Findings, delete only the new empty Engagement/Product/user after checking IDs and names. If evidence has been created, preserve it and disable only the dedicated identity; do not delete vulnerability records automatically. No changes to existing users, Products 1/2, Engagements 1/2, production Findings, Jenkins, K3s, GitOps or Docker configuration.
