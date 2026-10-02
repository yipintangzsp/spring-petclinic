# Petclinic 0.8 验收证据

- `before-*`：0.7 生产截图。
- `preview-*`：独立 H2 预览；其数据不代表生产。
- `after-*`：0.8 生产截图（上线验收后生成）。
- `comparison.html`：桌面/手机八个页面的前后对照。
- `browser-acceptance.py`：页面状态、溢出、国际化、JS 错误与业务导航检查，不提交有效就诊记录。
- `responsive-check.py`：320/768/1024 宽度、减少动态效果、键盘焦点检查。
- `final-release-acceptance.py`：只读核对 Argo、三副本、发行指纹、双架构镜像 digest、健康及 PostgreSQL 数据。
- `jenkins-status.py`：通过既有 relay 读取 Jenkins 状态；不输出凭据。
- `trigger-ci.py`：本次 #83 的调用记录，已运行，不应重复调用。
- `local-tests.log` / `local-build.log`：本地 46 项相关测试及打包日志。

截图保存在本地证据目录，避免把重复的大体积图片加入下一次 CI 检出。
