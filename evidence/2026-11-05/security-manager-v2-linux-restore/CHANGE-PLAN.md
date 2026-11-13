# Linux Gitleaks 最小变更审批单（尚未实施）

目标主机：devops / 192.168.64.11（Linux ARM64）。当前 HEAD：d8206deb。

## 为什么必须先批准

本轮只读取证发现 UID 65534 被现有 Prometheus、Alertmanager、Kyverno 等进程共用；不将它当成独立扫描身份。主机没有可复用的专用扫描账户或固定执行入口。按用户“新建受限账户、增加 SSH 授权或改变主机权限先批准”的要求，停止账户、文件权限和 SSH 授权写入，未运行扫描。

## 精确批准范围

1. **新增一个专用账户/组** `security-gitleaks`，UID/GID `24021`（预检均空闲）；密码锁定，无 sudo、Docker/988 或其他管理组。新建 `/var/lib/security-gitleaks`，由 root 持有且不可由账户修改。使用 `/bin/sh` 仅供 sshd 执行 forced command；SSH 密钥必须强制固定入口，不能开交互 shell。不修改 zhang、Jenkins、nobody 等现有账户。
   - 基础命令：`groupadd --gid 24021 security-gitleaks`；`useradd --system --no-create-home --uid 24021 --gid security-gitleaks --home-dir /var/lib/security-gitleaks --shell /bin/sh security-gitleaks`。执行前再次检查名称、UID、GID及目标目录冲突；任何冲突停止，不接管既有对象。
2. **仅在新测试域安装受审计文件**：`/var/tmp/security-manager-gitleaks-v2-linux-20261105`，root 所有、不可由扫描用户修改；其中 `package/`、`gitleaks`、`source-python/`、`approval.json`、`ssh-entry.py` 均固定。只有 `outputs/` 归 UID/GID 24021，模式 0700。安装过程只读取已有 containerd 缓存并校验 OCI blob 和固定二进制 SHA，不拉镜像、不创建容器、不调用 Docker API。
   - 复用 Gitleaks 8.30.1；期望 Linux ARM64 SHA256：`db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d`。
   - 镜像：`127.0.0.1:30050/platform-security/gitleaks@sha256:6b2d52241f9d176fc59e6e3b026ea52c98f390070587d9475d6ee2bc64941815`。
   - Clean 输入沿用历史公开测试文件 `app.py`：`# Disposable cross-project validation fixture` 和 `print("public clean fixture")`，重新生成真实 Git snapshot identity/目录绑定；不会重用旧 inode 或冒充历史执行。
   - 原 Runner、Source Lock、Policy、Artifact 和本地 Router 不改；新增入口只做固定 Clean 调用及受控结果导出。
3. **增加一把仅供该账户的专用 SSH 公钥**：Mac 私钥独立保存于 `/Users/zhangsir/.ssh/security-manager-v2-gitleaks`（0600），不复用生产管理员密钥、不放入 Git。仅新增该账户 home 下 root 所有的 `.ssh/authorized_keys`；权限 0600。
   - 公钥行强制选项：`restrict,command="/usr/bin/python3 -I /var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py"`。
   - 固定入口只接受 `clean-v1 web-<合法 UUID>`，Run ID 由现有 Web 后端生成；拒绝其他命令、参数、路径、stdin 载荷和交互请求。不得解释任何 shell 输入。
   - `restrict` 禁止 PTY、端口/Agent/X11 转发及 user rc；扫描用干净环境和 NoNewPrivs，实际校验 UID/GID/groups、CapEff=0、Docker/Kubernetes/生产凭证不可读。
   - 不修改 sshd_config，不重载/重启 SSH，不安装 systemd 服务，不修改 sudoers，不给该账户提权能力。现有 SSH 配置只读取证为 UsePAM=yes、PubkeyAuthentication=yes、StrictModes=yes，没有 AllowUsers/AllowGroups 限制。

## 批准后的实施和验证顺序

先建立新目录/身份/固定包，验证工具 OCI 来源、SHA、固定 Fixture 和真实身份权限，再执行一次 Clean。取实际退出码、Raw Report、单次 Policy、Artifact 与 Result Digest。只有该步骤通过后，验证 forced-command 拒绝 shell/任意参数/转发、超时和输出边界，再给现有 Web 后端增加显式受限通道配置。保留 Host/Origin/CSRF 和单任务保护。通过真实 POST /api/run 验证新 REAL 记录，重读/重启页面后核验 digest；不得把人工单次执行标记为 Web 触发。

## 风险与停止条件

新账户和新公钥扩大一个有限认证面；forced-command、root-owned 源文件、独立输出目录和负例验证是启用前提，不据此宣称完整容器隔离。身份、工具、资源、清理或凭证不可读检查失败立即停止，不改门限、不执行扫描。不会连接生产 Loki/Dojo。

## 回滚（无需重启任何生产服务）

1. 禁用本地 Linux 后端配置；保持页面可打开并 fail-closed。
2. 将**新账户**的 `.ssh/authorized_keys` 改名为 `authorized_keys.disabled`，禁止新会话；绝不编辑现有账户授权。
3. 等待受控任务完成/按其已记录进程域取消，确认 UID 24021 无剩余进程。不使用全局 kill 或影响 nobody 的命令。
4. 执行 `userdel security-gitleaks`，仅当专用组无其他成员时执行 `groupdel security-gitleaks`；不使用 userdel -r。
5. 验证真实路径、所有者及文件清单后仅删除两个本轮专用目录和该专用私钥/公钥。任何冲突或残留任务先停止删除；保留独立审计证据。
6. 验证页面退回明确 BLOCKED，生产节点、PetClinic、Jenkins、Argo、V1 Summary 和镜像不变。

审批范围不包括修改生产 Gate、K3s 工作负载、Jenkins 发布链、系统服务、Docker、已有账户/SSH 配置；不 push、不 release、不 rollout。
