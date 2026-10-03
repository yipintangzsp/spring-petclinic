# GitLab mirror availability on the 20 GB DevOps VM

Petclinic Jenkins build #97 passed tests, packaging and Sonar, then failed because `/api/v4/user` returned HTTP 502. At 2026-10-03 14:40:13 Asia/Shanghai, the kernel's global OOM killer killed GitLab's Puma Ruby process (~1 GiB RSS). nginx continued listening and Kubernetes reported the container Ready because no application probe was configured. Puma recovered at 14:44:06, after the mirror retries had expired.

The GitLab Deployment now requests 2560 MiB / 250m CPU and limits memory to 4 GiB. This changes its BestEffort QoS to Burstable and accounts for its normal memory usage in scheduling and OOM victim scoring. These values do not add physical RAM or guarantee that the shared node cannot exhaust memory. A startup probe allows up to 15 minutes for boot; readiness removes the endpoint when Rails is unavailable. No aggressive liveness restart was added. The existing local PVC stays on devops; Recreate avoids overlapping GitLab instances.

`infra/observability/gitlab-runtime-patch.json` is the focused strategic merge patch. Apply with `kubectl -n ns-devops patch deployment gitlab --type=strategic --patch-file=infra/observability/gitlab-runtime-patch.json` after backing up the live Deployment. The applied backup is root-only `/opt/petclinic-observability/backup/gitlab-before-oom-repair-20261003.json` on the server.

`gitlab-memory.rb` contains the persisted allocator configuration recommended by GitLab and the reduced Sidekiq concurrency (5). Existing Puma single mode (0 workers), Rails environment entries and monitoring configuration are preserved. The server keeps `/etc/gitlab/gitlab.rb.before-oom-repair-20261003` on GitLab's config volume. The recreated container reconfigures GitLab at startup; do not start a second concurrent reconfigure. For rollback restore the config backup and the exact original Deployment resource/probe fields, then restart GitLab.

The source mirror now waits up to 10 minutes for `/-/readiness` to report `status: ok`. An nginx 200 with unhealthy Rails cannot pass, hung responses are bounded, and access/configuration errors fail immediately. The authenticated mirror still verifies that GitLab main equals the source commit; failures cannot bypass deployment gates. Four HTTP regression tests run in Jenkins before Maven tests.

The DevOps VM remains at 20 GB. Avoid interpreting a successful run as proof that all 69 shared workloads can run at peak simultaneously. No workloads were disabled by this repair.

Reference: https://docs.gitlab.com/omnibus/settings/memory_constrained_envs/
