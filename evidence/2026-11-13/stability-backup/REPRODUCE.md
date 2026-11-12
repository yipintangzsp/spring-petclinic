# REPRODUCE — W13 稳定性 / 备份恢复演练 / 归档收口

环境：Mac 仓库 `~/code/petclinic-platform-20261011`（分支 `fix/security-manager-plugin-switches`，开工 HEAD `9852fde3`）；通道 `~/workspace/mac-access/{macssh,devssh}.sh`。全程只读＋本线点名操作，未 push。

## 1. 水位复核

- Mac：`df -h /System/Volumes/Data`、`uptime`、`vm_stat`、`sysctl vm.swapusage`（原件 `raw/watermark-20261113.txt`）。
- devops：`df -h /`、`df -B1 /`、`uptime`、`free -h`、`swapon --show`。
- 服务面：`KUBECONFIG=/home/zhang/.kube/platform-readonly.yaml kubectl get nodes / get pods -n petclinic / get applications -n argocd`。

## 2. D1 盘点（零删除）

- PV：`sudo du -s --block-size=1 /var/lib/rancher/k3s/storage/*`（目录名还原归属；只读 kubeconfig 对 PV/PVC 为 Forbidden，已实测记录）。
- devops-stack：`du -sh /home/zhang/devops-stack/*` 后逐级下钻 `ops-managed/`、`registry-data/docker/registry/v2/`。
- kubelet：`sudo du -sh /var/lib/kubelet/...`（含 volumes 对照）、`crictl images`、`docker system df`、`du` 于 `/var/lib/security-trivy`、`~/k8s-infra/.git`、`/opt/k3s-backup`。
- 结论与组合表见 `~/workspace/full-run-2026-11-13/disk-inventory-d1.md`（本目录 verification.json 有摘要）。

## 3. 恢复演练

原件 `raw/restore-drill-transcript.txt`。要点：源＝devops `~/k8s-infra/ns-data/mysql-full-backup.sql`（每日 02:00 备份产物）；隔离目标＝docker 容器 `w13-drill-mysql`（mysql:9.7，无端口发布）；awk 按 `-- Current Database:` 分段剔除系统库 `mysql` 后导入；information_schema 表数与 dump 内 CREATE TABLE 数对照（335=335）＋逐表 COUNT(*) 抽查；演练后删除容器、其匿名卷（按 CreatedAt 认定）与临时目录，并复核 docker system df 与 df 回到演练前数值。

## 4. T1 撤武装

- before：`cp .devsecops/security-view-kyverno-linux-v1.json raw/kyverno-arming-before.json`（sha256 双份一致）；全部武装文件清单 `raw/arming-inventory-before.txt`。
- 撤除：`rm .devsecops/security-view-kyverno-linux-v1.json`（与 Trivy 先例 item-6b2 同法：验收后删除武装文件）；after 记录 `raw/kyverno-arming-after.txt`（含时间与后果）。其余武装文件未动。

## 5. 归档核查

- `git status --porcelain` 分类计数；`git ls-files evidence/2026-11-13/` 与 `evidence/2026-11-12/` 核对各线证据入库；`~/workspace/full-run-2026-11-13/item-*.md` 清单核对。结果见 verification.json `archive`。
