# Candidate control rollback
Current safe defaults have already been restored: master enabled, all three plugins enabled, standard. Use the page's Restore Demo Defaults button for configuration-only recovery.

For code rollback, first confirm /api/runs has no RUNNING requests and stop only the local page with `node infra/security/manager-v2/view/control.mjs stop`.
Restore the nine exact root-owned release files from /var/tmp/security-view-config-backup-jndegfgk: for each gitleaks/semgrep/cosign, `entry` restores its workspace ssh-entry.py, `helper` restores package/infra/security/testing/<plugin>-linux-*.mjs, and `manifest` restores package-manifest.json. Preserve root ownership and 0444 modes. Use the same per-workspace execution.lock, and atomic file replacement as in update-execution-config.py. Do not change users, groups, keys, tools, fixtures or Jenkins proof wrapper.
Revert this local feature commit without touching unrelated working-tree files, then restart the local page with control.mjs start. Keep the local control JSON/history as evidence; it is not a production configuration.
No Kubernetes, Docker, Jenkins or production service restart is part of this rollback.
