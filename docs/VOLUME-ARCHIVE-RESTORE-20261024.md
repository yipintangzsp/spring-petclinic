# 获授权旧卷的恢复方法

本轮清理137个未引用匿名卷前，已保存完整归档并逐文件核对内容SHA256、属主、模式、符号链接与源内容稳定性。Mac私有备份目录为：

`/Users/zhangsir/code/evidence/platform-20261011/volume-archive-20261024`

`inventory.json` 是获授权范围；`verified-backups.json` 记录每个归档SHA256；`archives/<卷ID>.manifest.json` 是逐文件元数据；`deleted-volumes.json` 是实际删除清单。目录0700、归档0600。备份可能含旧数据库与凭据，按本机私有备份保存，不提交Git。

## 恢复单个卷

1. 从清单选择准确的64位十六进制卷ID。用Mac的 `shasum -a256` 校验对应 `archives/<卷ID>.tar.gz`，必须与 `verified-backups.json` 中该卷的 `archive_sha256` 完全一致。先核对归档，再创建任何目标。
2. 在服务器执行 `docker volume inspect <卷ID>`。如果目标已经存在，停止并检查，不覆盖原卷。确认不存在后才执行 `docker volume create <卷ID>`。
3. 在Mac把归档直接送入Linux解包，保留数字UID/GID、ACL、扩展属性与模式。将下方两处 `<卷ID>` 替换为同一清单ID；不要把非清单字符串拼入命令：

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 zhang@192.168.1.58 \
  'sudo tar --acls --xattrs --numeric-owner -xzpf - -C /var/lib/docker/volumes/<卷ID>/_data' \
  < /Users/zhangsir/code/evidence/platform-20261011/volume-archive-20261024/archives/<卷ID>.tar.gz
```

4. 按对应 `.manifest.json` 逐文件复核SHA256、UID/GID、模式、目录和链接目标，全部一致后再决定挂载到哪个容器。不要只按相似镜像名或文件名把旧数据库接入当前业务。若仅需检视，可先恢复到另一个全新隔离卷并保持只读。

本轮没有执行恢复操作。原来不在删除范围内的3个卷、所有Kubernetes PVC、当前数据库及Registry原件保留。归档保存于这台Mac，未宣称已有异地副本或已完成生产级容灾演练。
