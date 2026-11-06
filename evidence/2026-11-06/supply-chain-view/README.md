# Supply Chain Security view — read-only delivery

Page: http://security.devops.local:17862/#candidate-overview

Existing Candidate is verified by live read-only Harbor queries captured as a timestamped snapshot. SHA256 of registry index bytes matches exact digest; linux/arm64 and linux/amd64 children are present. Separate historical candidate build #2 and security audit #270 are linked by source commit, exact candidate digest, BuildKit metadata hash and existing archived signed-build verification. No new signing or cryptographic image-verification success is claimed. #270 is enforce security mode but PROMOTION_ACTION=audit-only; it is not release approval.

SBOM: actual archived #270 CycloneDX 1.6, 143 Maven dependencies; actual file SHA matches archived summary and source commit. Display includes 30 real component name/version/PURL rows plus the original authenticated Jenkins artifact URL. This is HISTORICAL / UNVERIFIED against candidate image digest. Same commit, targetScope, and a successful Maven SBOM stage do not establish in-image byte identity. No image extraction, build, scan or SBOM generation was attempted.

Signature: exact index and linux platform legacy .sig tags return 404. OCI referrers queries return 200 with empty manifests; Harbor accessories list is empty. Status SIGNATURE_MISSING / MISSING. Cosign verification NOT_EXECUTED_NO_SIGNATURE. Independent fixed-fixture Cosign PASS/FAIL remains separately visible and is not candidate trust evidence. No private key or signed artifact was created.

Release: NOT_APPROVED. Current pod image IDs use the previous running digest, so NOT_DEPLOYED. Argo Healthy alone is not used as candidate deployment evidence. Existing production configuration hashes, GitOps revision, socket mode and deployment generation unchanged. PetClinic 3/3, three nodes Ready, HTTP 200.

Web HTTP/API and original links checked. Source systems require login (Harbor 401, Jenkins 403, GitLab sign-in redirect without a user session); archive contents and Harbor reads were verified through existing authorized server-side access. Browser click NOT_TESTED. Source timestamps are shown; no background live polling is claimed.

Only view/data.mjs and view/app.js are wired. Existing index.html modifications from other work remain untouched. Rollback: revert this commit and restart only the managed local view after confirming no active run. No source-system rollback needed: this stage made zero production writes, builds, scans, push, releases or rollouts. Original Evidence Integrity remains FAILED; production Manager remains NOT_ACTIVE, canonical runtime remains 14/16.
