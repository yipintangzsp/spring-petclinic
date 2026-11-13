# SBOM production compatibility · 2026-11-01

**SBOM = VERIFIED**，范围限定冻结生产实现与 Policy Engine baseline-v1 / standard 的兼容性。171/171完整差分一致、drift=0；old/standard 均为 **PASS45 / FAIL121 / SKIPPED4 / NOT_CONFIGURED1 / WARN0**。Policy tests **1413/1413 PASS**（1236基线+177新增）。

这是SBOM库存生成/验收兼容，不是项目整体安全PASS、镜像SBOM attestation或新在线生成验收。没有运行Maven/CycloneDX、重建PetClinic、改CycloneDX输出、原Gate/发布流程/actual Summary、Argo CD或集群；没有rollout。本轮停止，不启动Regression或Summary。SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED、Sonar real negative=DEFERRED_REAL_NEGATIVE_EVIDENCE保持。

## 实现与生成模型

| 位置 | 当前行为 |
| --- | --- |
| `pom.xml` | Spring Boot parent 4.1.1；声明cyclonedx-maven-plugin，使用继承配置 |
| 本地已缓存parent/dependencies POM | generate-resources执行makeAggregateBom，application类型、JSON、输出`${project.build.outputDirectory}/META-INF/sbom/application.cdx.json`；plugin版本属性2.9.3。只读证据见local-parent-generator-config.json，未执行effective-pom或在线解析 |
| `resources/security-manager/petclinic-adapter.json` | 完整父命令 `( nice -n 10 ./mvnw -B package -DskipTests && node infra/security/sbom-verify.mjs )`，Maven非零则不运行verify |
| `Jenkinsfile` DevSecOps SBOM | 单独运行`node infra/security/sbom-verify.mjs`；本轮同时覆盖standalone |
| `infra/security/sbom-verify.mjs` | JAR/Maven原字节比较、输出原SBOM、原库存校验、source/hash summary与IO错误 |
| `infra/security/manager/tool.mjs sbom` | 通用插件接收显式checkout内文件，只做原通用schema验收，写native及manager报告，Lease/runtime前置和退出码保留 |
| `vars/securityManager.groovy` | SBOM配置能力、disable/off、原模块退出码、enforce缺配置、阶段异常与报告处理；在本地执行原文件 |

历史#270 console确认cyclonedx:2.9.3:makeAggregateBom；当前local parent配置与之对应，不把历史执行描述为本轮新生成。报告中收录限定行摘录和原console hash，没有复制无关日志。

## 原Gate规则与绑定边界

生产路径：

1. 原`unzip -p target/spring-petclinic-4.0.0-SNAPSHOT.jar META-INF/sbom/application.cdx.json`必须成功，超时30秒、maxBuffer8MiB。
2. JAR解出的**原字节**必须等于`target/classes/META-INF/sbom/application.cdx.json`。JSON语义相同但多一个换行也FAIL。
3. 创建输出目录并写`.devsecops/sbom.json`原字节，然后JSON.parse。
4. bomFormat必须CycloneDX、specVersion必须1.6；components必须数组且length>=10；dependencies?.length必须truthy。
5. 每个bom-ref必须truthy且全体唯一；不重新解释package身份或补做引用解析。
6. source从.git-sha trim读取；summary记录format/version、组件数、依赖节点数、原字节SHA256、JAR entry和Maven依赖范围。报告写失败也FAIL。

**143是历史计数，不是固定门槛。** 生产Gate最小10；142/10仍可通过。dependencies并未严格校验数组类型，metadata字段、dependency ref闭包也没有额外Gate；本轮冻结这些已有行为，不增加FAIL。

通用路径规则不同：配置文件路径必须在sourceRoot内，JSON的bomFormat必须CycloneDX且components为数组；无specVersion1.6、最低10、dependency或bom-ref唯一性要求。原native为JSON序列化结果，reportSha256对相同序列化字节计算。**历史通用plugin报告确实接受1.5、0组件**，新Policy不能把生产规则机械套到它上面。

### source/image/digest

实际已实现的artifact binding是**JAR entry与Maven output的原字节相等**，以及通用checkout scoped路径。summary/source/build字段是原报告身份标签，原SBOM脚本没有校验git commit格式/checkout真实性或签名。

当前上述SBOM Gate **没有candidate/final image digest绑定**，也不读取SBOM image字段验证所属镜像。image/digest mismatch Gate样本=0，明确NOT_APPLICABLE（不存在该分支），不能声称证明了“另一个镜像SBOM被拒绝”。本轮没有发明一个digest Gate，也没有把缺少image绑定宣传为已具备的能力。原artifact byte/path mismatch有6个样本；它们不等同镜像digest mismatch。

另一个scanner的漏洞事实不属于本Gate：components数量、package metadata乃至BOM中的vulnerabilities属性都不会被转换成severity或漏洞Gate。三个专门样本确保库存验收不变成风险判断。

## Adapter与完整原实现对照

新增`infra/security/policy/sbom-parent.mjs`、`sbom-observations.mjs`、`sbom-test-harness.mjs`、两份test及Groovy harness、versions/sbom-parent-baseline-v1.json。`evaluate`仅对带stage的SBOM完整事实分派新parent；旧6份纯字节差分接口保留，不改旧Gate或生产Manager。

parent消费原generator status、extraction status/bytes、原Maven字节、文件/IO观察、runtime/Lease、通用config和wrapper报告。库存保留原纯sbomEvidence规则；rawEvidence不变，仅追加独立normalizedFacts和decision。没有推断severity、依赖风险或镜像身份。缺未采集观察返回NOT_TESTED/decision=null，与真实文件ENOENT导致FAIL区分；wrapper的audit缺配置保留NOT_CONFIGURED，off/disabled保留SKIPPED。

旧Gate oracle执行完整未改控制流的sbom-verify.mjs、generic tool.mjs的实际SBOM分支和原scanner-runtime前置函数，使用冻结外部输入及内存输出替身。新parent独立走原校验/聚合谓词；比较PASS报告字段、外部文件/IO顺序和raw不变。

production完整父命令还在真实本地`/bin/sh`执行原`&&`表达式：nice/node替换为临时无外部操作stub，返回同一冻结Maven/旧verifier状态并记录调用顺序。原Maven未执行；非零generator后只有一次stub调用，verifier不会调用。并非仅parser测试。

Shared Library：本地固定Groovy2.4.21执行**未修改vars/securityManager.groovy**，Jenkins DSL均为无外部操作替身。generic使用真实java-web profile并显式禁用其他工具；production资源计划在harness中**仅选原SBOM项**，这是SBOM isolated wrapper证明，不冒充整个平台所有模块的汇总兼容。其他Provenance入口仅stub skipped，不开始它们工作。

原wrapper的checkout/Lease/credentials/stage/write/archive等异常纳入对照；actual Summary只保留inert步骤，不读取生成结果、不执行真实summary脚本。当前SBOM模块findings/blocking=0，不制造非真实exit10来增加WARN；audit扫描执行错误仍FAIL。audit缺配置保持NOT_CONFIGURED，enforce缺配置失败，off/disabled不计PASS。

## 证据分类与复核

- **REAL_HISTORICAL**：#270 sbom.json、sbom-summary.json与通用contract-audit#4 sbom-native.json、sbom-manager.json，4份原样复制。#270 BOM为CycloneDX1.6、143组件、144依赖节点，SHA256=`b0a9ab3d854212e8ff6ace34cfd683775ce32cac955b9d41e038dca78dc2b3f3`与summary一致；generic报告1.5/0组件保留。原件hash和路径见historical-index.json。
- **CONTROLLED_REPLAY**：171个完整输入（JS126：standalone38/production43/generic45；原Groovy45）。受控错误和生成状态是synthetic冻结观察，不能说成真实生产事故。
- **SYNTHETIC_UNIT_ONLY**：6个辅助项（历史hash复核、缺证、low/strict/override行为），不计171完整差分。完整历史generator/prerequisite/JAR transcript样本=0。

分类：库存分支53、missing8、malformed12、artifact byte/path binding6、Maven generation failure5、JAR extraction failure10、prerequisite4、infrastructure1、IO8；其他未强制语义/历史generic/inventory-not-risk另见acceptance。wrapper的异常单独计入45样本。

171份落盘fixture已重载并核对输入SHA、decision与raw不变；原SBOM内容、格式版本、组件身份/数量、package metadata、source/report标签、generator观察均保留。测试不会声称保留了原本不存在的image attestation。

全套Policy在临时隔离副本运行，只回拷本轮目录结果，临时副本finally删除。**1413/1413 PASS，已验收Cosign/Provenance/Build Provenance847份文件零变化**；108份原安全源及12份本轮保护源文件不变。未重写旧证据矩阵，只另存本轮SBOM coverage更新。

## 23项验收

| 项 | 结果 |
| --- | --- |
| 1 production locations | 上述POM/资源映射/Jenkinsfile/verifier/generic Manager/Shared Library |
| 2 format/version | 生产CycloneDX1.6；generic仅CycloneDX+components数组，不强制版本 |
| 3 generator | 继承CycloneDX2.9.3、makeAggregateBom；原Maven&&verify不变 |
| 4 artifact/digest binding | JAR/Maven原字节与checkout路径；image digest binding不存在，未伪称已验证 |
| 5 checks | 原生产>=10、dependencies.length、唯一非空ref；generic独立宽规则保留 |
| 6 adapter | YES |
| 7 historical | 4份artifact+1份生成日志限定摘录；历史完整执行差分0 |
| 8 replay | 171完整差分 |
| 9 synthetic | 受控重放故障/外部状态；另6辅助unit-only，均无生产生成 |
| 10 valid | PASS45，限SBOM库存/所选wrapper范围 |
| 11 missing/malformed | 8 / 12个专门脚本样本 |
| 12 mismatch | 6个artifact字节/路径；image digest为0/NOT_APPLICABLE，非通过 |
| 13 execution/prerequisite | generator5、extraction10、prerequisite4、infrastructure1；另wrapper异常 |
| 14 IO | 脚本8；另wrapper写入/归档等异常 |
| 15 old decisions | PASS45 / FAIL121 / SKIPPED4 / NOT_CONFIGURED1 / WARN0 |
| 16 standard decisions | 完全相同 |
| 17 complete differential | 171 |
| 18 matched/mismatched | 171 / 0 |
| 19 raw preserved | YES，171落盘重验；历史原件、847已验收artifact无变化 |
| 20 gaps | 原JAR/Maven文件体、完整历史generator/CLI/prerequisite transcript未全部归档；新实际生成/live/CPS/镜像attestation未验，不冒称通过 |
| 21 SBOM final | VERIFIED，仅冻结生产路径baseline-v1/standard兼容性 |
| 22 Policy tests | 1413 PASS / 0 FAIL；本轮177新增 |
| 23 leave compatibility | YES，仅SBOM。本轮停止 |

证据目录：`evidence/2026-11-01/sbom-parent/`。acceptance.json为机器验收，differential.json/workflow-differential.json为逐样本记录，historical、historical-index.json、historical-generator-log.json保留历史，source-preservation.json/persisted-fixture-check.json/isolated-regression.json/policy-tests.log/artifact-sha256.json用于复核。

在仓库根运行本轮测试：`node --test infra/security/policy/sbom-parent.test.mjs infra/security/policy/sbom-workflow.test.mjs`。Groovy jar沿用前轮固定本地2.4.21，`PROVENANCE_GROOVY_JAR`可指定路径，SHA256=`de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0`；缺失/hash不同明确失败，不自动联网或跳过。全套测试需隔离副本以避免其他测试更新其生成证据，本轮隔离执行记录已保存。
