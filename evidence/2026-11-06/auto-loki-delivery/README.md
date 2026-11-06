Automatic Loki delivery — 2026-11-06

One existing Web API Semgrep Clean request produced a new REAL result; the Web completion path called the existing Result Router/Loki Consumer. There was no manual Consumer call, replay or second scanner invocation. Policy evaluated once. `verdict.json`, `real-run.json`, `router-receipt.json`, `query-proof.json`, and `grafana-query.json` bind the same Run ID and Result Digest.

The existing authorized strict-host-key SSH local forward is created only for delivery/query, forwards only the fixed existing Loki target, and is closed before completion. It is not a new daemon or API. One low-cardinality event is sent; Run ID and digests are body fields. Raw reports, secrets and scanner source are not sent. DELIVERED requires HTTP 204 plus a matching Loki query. Grafana is verified separately with the existing non-admin account, without changing the Dashboard or permissions. The per-run link supplies exact project/run/digest and time window.

Legacy Router entry points and Consumer dry-run defaults stay unchanged. Disabled/error scans do not trigger real delivery. Delivery failures are recorded separately and cannot turn a failed Policy into PASS. New records are written separately from immutable scan artifacts and existing history.

Six focused adapter tests and thirteen applicable existing Consumer tests passed. The earlier failed local test was a noncanonical macOS temporary path, corrected before the sole real scan. Browser clicks were NOT_TESTED; actual Web HTTP/API trigger, persistence, automatic delivery, query-back and Grafana datasource API were verified.

Rollback if needed: revert this local integration commit, then restart only the managed local page using `node infra/security/manager-v2/view/control.mjs restart` after confirming no run is active. Keep the real run and Loki evidence; do not rewrite or delete historical logs. No production service, account, permissions, Gate, GitOps, image, V1 Summary or Dashboard rollback is needed. Release=0; rollout=0.
