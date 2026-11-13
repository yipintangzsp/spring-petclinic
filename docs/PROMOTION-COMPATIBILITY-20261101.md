# Promotion / Security Approval compatibility · 2026-11-01

**Promotion = VERIFIED**，仅当前冻结生产验证路径与Policy Engine baseline-v1 / standard的兼容性。**258/258 MATCH、drift=0；old/standard均为PASS16 / FAIL239 / SKIPPED3**。本轮新测试269/269 PASS；前基线1604，累计已验证1873。未全量重跑1873。

未签发真实批准、生成真实生产签名、改approved digest、改Git/release state、运行Docker/kubectl或查询Argo、发布PetClinic。原Gate/actual Summary/发布流程未改，无rollout。所有模拟批准、Git与部署行为只在内存替身及本轮标记证据中；其SYNTHETIC_SIGNATURE不能用于生产授权。**本轮停止，不启动Summary。** SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED及Sonar real negative=DEFERRED_REAL_NEGATIVE_EVIDENCE保留，不宣称全平台收口。

## 生产实现与两个现有发布入口

| 位置 | 当前职责 |
| --- | --- |
| `infra/security/promotion/evidence.mjs` | gateEvidence读取当前Gate/summary/业务快照；candidateSbom从固定candidate的amd64/arm64本地镜像取JAR内SBOM，记录hash |
| `infra/security/promotion/contract.mjs` | validateGate、approvedRelease、promotionInput三个原契约，未重写 |
| `infra/security/promotion/sign-approve.mjs` | 既有Lease/tools、安全Gate资格、candidate/children Cosign sign+verify、pending批准blob签名、cleanup、最终rename |
| `infra/security/promotion/promote.mjs` | 原dry-run/deploy批准验证、GitOps源/并发、blob verify、精确image变更、发布验证与有限rollback |
| `Jenkinsfile.security-audit` | 三个原stage：Candidate Approval Evidence、Candidate Sign and Approve、Approved Promotion；when按action/currentBuild选择 |
| `infra/observability/promote-private.mjs`、`gate-contract.mjs` | 常规Jenkins发布入口，校验private main/source、built/scan digest、既有signed release proof并更新release metadata |
| `Jenkinsfile` Git Promotion | 原release-preflight→credential→promote-private；本轮覆盖其父阶段失败传播，不认证实时基础设施preflight结果 |

已先只读盘点，无适用AGENTS.md。没有给两条既有路径发明共同的新批准模型：audit security-approval路径使用approved-release.json/sig；常规private-main路径使用既有signing-release.json/release-evidence.json。二者各自的原验证保留。

## 什么叫“approved for promotion”

### 安全资格

原validateGate要求result=SUCCESS、有效正整数build、40位小写source；固定Harbor candidate digest；Trivy为candidate scope且目标等于candidate；summary目标/source/build与Gate一致，C/H严格为0，两份架构scan存在。

sourceScan/admission/semgrep/zap/falco/dojo/kubescape必须success；**若child.source存在**才比较当前source，缺source字段不新增FAIL。business.unchanged、原runtime固定digest、candidate-bound两架构SBOM（amd64/arm64各一、JAR/SBOM hash格式）必需。这里的candidate-SBOM约束是原Promotion契约，**不是修改上轮不绑定image的普通SBOM Gate**。

### 批准与签名

sign-approve先验证Gate，再用原key对candidate index及两个Trivy child digest签名并验证；每份verified claim必须等于该digest。approvedRelease调用原validateGate，要求相应verified images存在，构造schema1、APPROVED/SUCCESS、jenkinsBuild/securitySourceCommit、candidateImage、candidateDigest=approvedDigest、previousRuntimeImage、SBOM和verifiedImages。

原脚本写pending→sign-blob→verify-blob；finally清理私钥并写approval-signing报告，完成后才rename最终批准json/sig。签名失败不能出现最终rename。Policy不调用approvedRelease，不生成pending/final artifact或批准token。

### 消费批准与连续性

promote再次验证当前gateEvidence，要求批准的jenkinsBuild=当前BUILD_NUMBER、securitySourceCommit=当前source、candidateImage=当前candidate；approval-signing.status=success且临时私钥已清除。原Cosign verify-blob必须成功。

promotionInput要求APPROVED/SUCCESS、candidateDigest=approvedDigest、candidate URI与approvedDigest一致，previousRuntime URI合法；GitOps manifest恰好一处既有image，必须仍是批准记录里的previousRuntime，防止覆盖其他发布。

原Argo repo/targetRevision必须为既有private main，clone后ls-remote main仍等于原base才继续。dry-run只输出patch/报告，不commit/push/等待rollout。deploy原代码commit/push后检查Argo revision/UID/Synced/Healthy、Deployment与全部目标Pods、HTTP200/health UP。发布后失败只有远端仍等于本次commit才允许原rollback；rollback收敛后原脚本仍抛错，**Gate FAIL**。

### 常规private-main路径

原helper验证私有origin、origin/main仍等于本次source、build digest=Harbor Success双scan digest、K8S_IMAGE相同、原signed release/source proof及verified index signature；只按原promoteManifest更新既有image与release metadata。没有将此路径强行改为新增approved-release token要求。

## 原来没有的规则不会加入baseline-v1

- approved-release.createdAt没有TTL/expiry Gate；旧时间但build/source/digest/签名等仍符合时，原代码不因年龄FAIL。
- 此批准路径没有独立强制Provenance/image-build predicate验证；不得把前轮VERIFIED工具变成新必需条件。
- 部分child.source可缺省是原条件；没有补成新的schema要求。
- sign-approve中cleanup.exists=true只记录temporaryPrivateFilesRemoved=false，原签发脚本不据此单独FAIL；消费promote时原逻辑会拒绝该flag。两个阶段区别保留。
- checkedEvidence辅助函数不是当前生产入口，本轮没有修复或启用它。

因此VERIFIED仅证明“忠实兼容”，不是为当前授权流程补齐理想的安全性质。

## Adapter与不自批准

新增promotion-evidence.mjs、promotion-replay.mjs、promotion-fixtures.mjs、两份测试/Groovy harness、版本锁；Policy仅增加security-approval-promotion分派。原生产脚本不改，不接实际Summary或release。

old side运行未修改控制流的evidence/sign-approve/promote/private-main和原runtime/contract。所有fs写、rename、Git、Cosign/SOPS、Docker/unzip、kubectl、HTTP都是内存观察/结果替身，没有真实进程或远端mutation。private-main只对原import.meta入口判断注入测试身份以覆盖原main，其验证谓词和流程不改。原安全规则/批准生成模型不重写。

Policy只消费原execution/reports/observations。完成状态/必要报告未采集返回NOT_TESTED/decision=null，不拿PolicyDecision=PASS充当批准。低/严格等级和audit/override不软化冻结FAIL。报告中的candidate/approved/build/source、marker、signature引用作为原事实保留，Policy不重算生成它们。

**circular/self-approval check=PASS：** old不读Policy输出；Policy module不import原approvedRelease或签名/执行器；在拦截write/rename/copy的测试中只读无写，无法签发或更新批准。raw input缺approval即使自带policyDecision也不被当作完整原验证。失败批准验证未触及Git，失败sign-blob/verify-blob未完成最终rename。

## 历史与受控证据

**REAL_HISTORICAL：2个完整接受样本。** #259原dry-run、#260原deploy，12份原artifact复制并核对原件hash（approved-release.json/sig、approval-signing、candidate-sbom、dry-run和promotion-result）。两份原批准blob签名均用现有公钥本地重验通过，没有生成签名。

#259是DRY_RUN_PASS、runtime不变、没有GitOps commit；#260为DEPLOYED、原commit 340ef4b8c74e3c2a5820da8d98b0f134283bb8d9、Argo Synced/Healthy/3 Ready/HTTP200历史记录。只说明历史行为，不当作本轮服务健康或新发布。

**CONTROLLED_REPLAY：256完整输入。** 原操作路径234个含2历史，即232 controlled；原Jenkins stage fragment24个controlled。包含candidate-sbom/sign-approve/dry-run/deploy/private-main全部路径及错误、并发和rollback。原stage fragment在本地固定Groovy执行，DSL无外部操作；actual Summary命令仅inert步骤，不执行/修改Summary。常规Git Promotion preflight仅失败传播观察，不运行基础设施任务。

**SYNTHETIC_UNIT_ONLY：11辅助项**，包含缺证、无self-approval、无Git写、无签发、low/strict/override、rollback仍FAIL等，不计完整差分。

完整结果：258=234原操作+24原Jenkins条件/父stage，PASS16/FAIL239/SKIPPED3。audit-only、前序FAILURE/UNSTABLE导致原批准stage未选择时是SKIPPED，不改成PASS。未创造WARN/NOT_CONFIGURED分支。

专门操作分支计数：missing-approval2；digest20、build6、source30、identity8、malformed10、concurrency7、signature14、eligibility47、execution16、prerequisite13、IO26、infrastructure4、rollback3，其他原边界及父stage另列。不是生产事故数量。

258份落盘facts/输入重载核对SHA、decision、raw不变；16份保护源码/manifest与HEAD一致，108原安全源、此前**1268份已验收artifact**无变化。历史approval及digest/signature从未覆盖。

## 24项验收

| 项 | 结果 |
| --- | --- |
| 1 locations | 上述promotion四文件、private-main/gate-contract、两Jenkins入口 |
| 2 exact contract | 原Gate资格→原批准签名→当前批准验证→GitOps连续性/父stage |
| 3 approval semantics | 原APPROVED/SUCCESS签名记录；Policy不签发 |
| 4 candidate/approved digest | 原URI/digest相等、claim验证、blob签名及current candidate绑定 |
| 5 build/source | 当前Gate/summary、批准与build/source严格原比较；private-main原source连续性 |
| 6 security eligibility | 原stage status、候选Trivy C/H0、双架构SBOM、business稳定等，不新增规则 |
| 7 adapter | YES |
| 8 historical | #259 dry-run/#260 deploy两样本，12 artifact，原签名本地重验2份 |
| 9 controlled | 256完整重放，无真实mutation |
| 10 synthetic | replay故障/OS/CLI/部署替身；另11辅助测试 |
| 11 missing approval | 2专门样本 |
| 12 digest/build/source | 20 / 6 / 30 |
| 13 stale/foreign/malformed | 原同build/source/concurrency/identity检查保留；malformed10；createdAt不新增TTL |
| 14 execution/prerequisite/IO | 16 / 13 / 26；infra4、rollback3及父stage错误另列 |
| 15 old decisions | PASS16 / FAIL239 / SKIPPED3 |
| 16 standard | 完全相同 |
| 17 complete differential | 258 |
| 18 matched/mismatched | 258 / 0 |
| 19 circular check | PASS；没有Policy自批准/签名/写状态 |
| 20 raw preserved | YES；258重载，1268前证据零变化 |
| 21 gaps | 历史每调用前置/CLI transcript不全；live CPS/Cosign/Git/cluster健康未验，不冒称新生产授权 |
| 22 final Promotion | VERIFIED，限定frozen production source baseline-v1/standard兼容 |
| 23 Policy tests | 本轮269 PASS/0 FAIL；累计1873，未全量重跑 |
| 24 leave phase | YES，仅Promotion；停止，不开始Summary |

证据目录`evidence/2026-11-01/promotion-parent/`：acceptance.json、differential.json、workflow-differential.json、fixtures、historical-index.json、historical、source-preservation.json、persisted-fixture-check.json、no-circular-self-approval.json、artifact-safety-check.json、policy-tests-new.log、production-coverage-update.json、artifact-sha256.json。

本轮复核：`node --test infra/security/policy/promotion-parent.test.mjs infra/security/policy/promotion-workflow.test.mjs`，只运行原代码在内存替身上的兼容测试与本地Groovy，不调用真实生产工具。Groovy沿用本地固定2.4.21，PROVENANCE_GROOVY_JAR可指定；SHA256=de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0，缺失/hash不同明确失败，不自动联网。临时Groovy输入目录finally删除；无真实私钥/Secret读取或权限扩大。
