# Existing security build → Harbor association

VERIFIED: Commit 9a78cc89f22fa98fb1ffcc43e2ae279299471793 is bound to
petclinic-ci #270's archived V1 Security Summary and completed enforce Security
Gate (no FlowGraph errors, module exits 0, overall SUCCESS). Its exact
 auditTargetImage is sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55.

The image-producing Job is explicitly separate: petclinic-candidate-build #2.
Its original BuildKit metadata and signed build predicate bind that exact source,
builder identity, build number and output digest. #270's separately signed
security-validation predicate binds the same source/target to security build 270.
Existing public-key verification functions were reused offline; no scanner,
Cosign command, Policy evaluation, registry write or new build was executed.
Wrong commit/digest checks rejected cross-association.

Harbor authenticated GET at 2026-11-05T14:24:40Z returned HTTP 200, artifact 690,
repository petclinic/petclinic, tag 0.10.0-ci-1000002, exact same digest. Tag is
only reported from the query; it is not the source of Commit attribution.

The Overview shows Jenkins data as HISTORICAL and Harbor as a dated LIVE-query
snapshot; refreshing does not query production. Both actual page GETs were 200.
Authenticated Jenkins build/summary/proof APIs were 200. GitLab commit API matched;
its anonymous browser link redirects to login. Harbor home is 200; the private
artifact link is 401 anonymously and 200 with existing authorized API identity.
Browser clicking remains NOT_TESTED. No production credentials enter the page.

Current production snapshot at 2026-11-05T14:28:11Z: three nodes Ready, PetClinic
3/3, HTTP 200, Argo Synced/Healthy, generation 175 and deployed digest unchanged;
Docker socket 0660. Production Job config and V1 Summary hash match prior known
values; last production build remains 270. No permission changes or new builds.

This does not join security-gitlab-push-demo #4 to a Harbor image, certify the
current runtime image's provenance, claim candidate promotion, or advance V2
runtime from 14/16. No production release/rollout, Git push or remote writes.

Rollback: revert only this round's local page card in index.html; no production
configuration or service rollback is required. Existing historical evidence is
unchanged. See sources.json, archived-proof.json, verified.json,
http-acceptance.json and production-health.json for evidence.
