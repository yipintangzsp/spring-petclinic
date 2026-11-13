# Build Provenance compatibility · 2026-11-01

**Build Provenance = VERIFIED**，限定当前冻结生产实现与 Policy Engine baseline-v1 / standard 的兼容性。不是新生产构建、在线签名/registry 验收或 SLSA 认证。

完整差分 **363/363 MATCH，drift=0**：原 JS 脚本329个输入，原 Shared Library Groovy34个输入；old/standard 均为 **PASS30 / WARN7 / FAIL322 / SKIPPED4**。359个输入有 Gate decision，4个明确 off/disabled，未计PASS。Policy tests **1236/1236 PASS**（864基线+372新增）。

本轮停止，不开始 SBOM、Regression、Promotion 或实际 Summary 集成。SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED、Sonar real negative=DEFERRED_REAL_NEGATIVE_EVIDENCE 保持，不能输出全平台验收成功。

## 当前实现和证据模型

| 入口 | 实际实现及范围 |
| --- | --- |
| `Jenkinsfile.candidate-build` | producer的 Compile Candidate / Build Dual Architecture Candidate / Preserve Candidate in Harbor / Attest Actual Image Build。只读盘点，不执行流水线 |
| `infra/security/provenance/build-record.mjs package` | 原Git clean source/identity→`nice -n 10 ./mvnw package -DskipTests`→source复查→JAR SHA256及编译receipt |
| 同文件 `image` | 匹配compilation source/builder/JAR、固定local tag、tag不存在、context前后连续性、Buildx命令、metadata/index digest及双架构检查 |
| `infra/observability/publish-artifacts.mjs harbor-copy` | 原blob/manifest递归传输、重试、source/destination digest header相等、包含两种arch、报告 |
| `infra/security/provenance/build-attestation.mjs create/verify` | 原显式expected、tools/lease、predicate验证、既有key签名及立即验证、digest/source/builder/tamper负控制、报告/cleanup |
| `build-contract.mjs` / `contract.mjs` | 原 validateBuildStatement / verifyEnvelope，不改写算法 |
| `vars/securityBuildProvenance.groovy` | 原optional/模式/explicit identity/verify调用、audit WARN或enforce FAIL、异常与报告 |

重任务Lease获取、release-preflight和离线包prepare属于已有前置流水线，已盘点、没有运行或改造；本轮证明上述Build Provenance路径的兼容性，不认证整条Jenkins部署流程。Harbor-copy是构建产物保存路径，本轮仅冻结原分支，不处理Promotion。

### Source、81项输入及Maven

producer读取Git HEAD与remote，要求40位小写hex、既有可信repository模式；检查既有src/pom/Dockerfile/.dockerignore/mvnw/.mvn/runtime/provenance路径未改。Maven前后source必须相同。

`.dockerignore`必须等于原允许的六个模式。context是Dockerfile、.dockerignore、JAR以及递归security-packages中的普通文件；禁止symlink/非普通文件。排序后的名称及原SHA256事实在Buildx前后必须相同。

**81是producer #2归档的context条目数，不是全部Git源码清单或固定81项的Gate要求。** 本轮保留完整81项name/checksum，并逐项建立81个前后checksum变化的FAIL replay。历史文件体未全部归档，所以不声称重新计算了这81个历史文件的哈希。

Maven receipt保存source/builder、起止时间、sourceCommit、jarSha256；image阶段要求receipt的source/builder与当前一致、当前JAR checksum一致。原Maven使用-DskipTests，不修改。依赖解析非hermetic的原limitations保留。

### BuildKit、架构和digest

原命令为 `docker buildx build --platform linux/amd64,linux/arm64 --provenance=mode=min --metadata-file ... --tag ... --push .`。原metadata字节SHA256保存到buildkit.metadataSha256；containerimage.digest必须合法并等于registry index原字节SHA256；index恰有一个linux/amd64与一个linux/arm64。Harbor-copy要求两种架构存在，逐manifest核对source/destination digest header相等。

归档有两份native `buildx.build.provenance/linux/<arch>`；本轮复用而不发明新校验。producer当前没有检查这些native内部所有字段，consumer也不运行BuildKit。

签名predicate要求subject恰一个、digest等于expected image，candidateImage等于完整expected ref；source commit/repository、builder identity/buildNumber必须匹配；编译JAR checksum、compilation.sourceCommit、非空context及checksum格式、metadataSha256格式、platforms精确顺序、chronology保持原验证。

### 原实现未强制的边界

这些没有通过本轮重构悄悄新增FAIL：

- consumer不要求context固定81条，不重新读取文件体或计算checksum；合法格式的checksum换值、80条仍遵循原验证结果。
- consumer不额外比较buildkit.outputDigest与subject；producer先前生成/验证链与consumer检查范围分别记录。
- Harbor-copy按tag递归复制，比较source/destination manifest header；**不读取build-provenance.json做跨receipt对比**。若tag已换成另一份源/目标一致的index，原copy本身仍可成功。专门PASS差分记录这个边界，不宣称端到端存在额外校验。
- 原临时目录cleanup操作抛错会FAIL，但exists=true仅令temporaryPrivateFilesRemoved=false，不据此新增FAIL。

因此VERIFIED表示忠实兼容，不表示以上边界已经强化或全链路达到更严格标准。

## Adapter与验证方法

`build-provenance-evidence.mjs`消费版本化、完整、带inputIdentity/phase的执行及原验证观察，输出独立normalizedFacts/Policy decision。缺完整性、退出状态、必要成功报告或verified envelope时为NOT_TESTED/decision=null；不把缺证PASS。unsupported成功事实不接受。错误诊断、阶段、原报告、checksum/身份/架构观察保持不变，不虚构severity。

**Policy不调用verifyEnvelope、validateBuildStatement、BuildKit或源码hash。** 原生产验证仍负责证明事实：`build-provenance-replay.mjs`是仅用于CONTROLLED_REPLAY的collector，运行未改控制流的原脚本和原验证函数，所有Maven/Buildx/CLI/network/fs写均替换为冻结观察。collector不由Policy调用，也未接生产执行。退出状态来自完整原执行，不是fixture中的手写oldDecision。

真实验证函数对签名/BuildStatement产生的事实、checksum测量事实保存在observations；producer文件体缺失时提供明确标记的历史checksum观察，不伪装成新计算。synthetic registry index bytes由测试构造并使用其真实派生digest，明确不是原历史index bytes。

workflow adapter只消费与cfg explicit identity绑定的verify事实；直接用本地固定Groovy运行**未修改的securityBuildProvenance.groovy**，Jenkins DSL替身无外部行为。enforce非零FAIL、audit非零WARN；stage/withEnv/credentials/writeJSON等异常仍FAIL。off/非boolean启用路径SKIPPED。没有调整opt-in或控制开关。

版本锁绑定原源码、tools与公钥；源码改变需重验，不静默沿用旧结论。所有新增文件在infra/security/policy/build-provenance-*及versions下；evaluate仅增加未生产接入的build-provenance分派。actual Summary/原Gate/原Shared Library未改。

## 证据分类

- **REAL_HISTORICAL**：producer `petclinic-candidate-build #2` 的7份artifact原样复制，保留原路径/hash；#270原build envelope/report复用。producer Maven receipt与签名predicate一致，81项输入保留；原metadata字节hash等于签名predicate记录，两份native架构数据存在；candidate/outputDigest一致。原可信公钥本地重验历史签名成功。
- **CONTROLLED_REPLAY**：363个完整输入。JS329=package21/image129/Harbor-copy43/create72/verify63/invalid1；Groovy34。历史数据加明确构造的故障/registry/命令观察。不是新的真实构建或历史事故。
- **SYNTHETIC_UNIT_ONLY**：9个缺证/输入绑定/Policy无源码读取等辅助测试，不计363个完整差分。replay中的修改签名predicate使用临时内存测试key，私钥从不导出/落盘；不是生产签名。

专门分类：checksum97（含81逐项连续性）、source17、builder13、architecture12、digest10；execution6/infrastructure45/IO34；其余missing19/malformed20/tamper7等详见逐样本记录。workflow错误另列，分类没有混成生产事故统计。

没有新Maven、Buildx、SOPS/Cosign命令执行、registry请求或生产签名；没有PetClinic重建/发布。所有真实production credentials值未读取。

## 26项验收

| 项 | 结果 |
| --- | --- |
| 1 implementation | 上述producer、build-record、Harbor-copy、build-attestation、contract、Shared Library |
| 2 source/input model | clean Git/source连续性及排序context前后比较，原行为 |
| 3 checksum | 归档81项；原SHA256观察；逐项81个continuity FAIL，不由Policy重算 |
| 4 Maven | 既有package/JAR/编译receipt，保留非hermetic限制 |
| 5 BuildKit | 原metadata hash、index digest、mode=min事实 |
| 6 architecture | 原producer index、copy与consumer各自校验不变 |
| 7 builder | 当前producer身份与consumer显式expected严格绑定 |
| 8 candidate/final | 原index字节digest、copy header相等、签名subject/candidate绑定；跨receipt缺口如实保留 |
| 9 adapter | YES |
| 10 historical | producer7份artifact、consumer#270相关证据；非新在线执行 |
| 11 controlled | 363完整replay |
| 12 synthetic | 构造负例/registry/临时测试签名属于replay；另9个unit-only辅助项 |
| 13 checksum mismatch | 97（含81项continuity） |
| 14 source/builder | 17 / 13 |
| 15 architecture | 12 |
| 16 digest | 10 |
| 17 execution/infra/IO | 6 / 45 / 34，另workflow异常 |
| 18 old decisions | PASS30 / WARN7 / FAIL322 / SKIPPED4 |
| 19 standard | PASS30 / WARN7 / FAIL322 / SKIPPED4 |
| 20 complete differential | 363，其中359决定、4明确跳过 |
| 21 match/mismatch | 363 / 0 |
| 22 raw preserved | YES，363份落盘重载SHA与decision复核；历史原件不变 |
| 23 gaps | 历史81个文件体、raw final index、完整CLI/prerequisite transcript未补；live/CPS健康未验。不声称新在线验收 |
| 24 final | VERIFIED，仅冻结production source与baseline-v1/standard兼容 |
| 25 Policy tests | 1236 PASS / 0 FAIL；隔离副本回归，原验收证据不覆盖 |
| 26 leave phase | YES，仅Build Provenance。本轮停止 |

## 复核与文件

报告机器证据在 `evidence/2026-11-01/build-provenance-parent/`：acceptance.json、differential.json、workflow-differential.json、fixtures、historical-index.json、historical-build-binding.json、persisted-fixture-check.json、source-preservation.json、isolated-regression.json、policy-tests.log、production-coverage-update.json、artifact-sha256.json。

Policy tests全套在临时隔离工作目录运行，只回拷本轮结果，临时副本finally删除。已接受Cosign/Provenance证据463份byte-for-byte不变，原108份安全源与15份本轮保护文件不变。清除了仅本轮生成、已不被任何差分记录引用的5份旧fixture，不涉及历史或已接受证据。

新测试可从仓库根用 `node --test infra/security/policy/build-provenance-parent.test.mjs infra/security/policy/build-provenance-workflow.test.mjs` 复核。Groovy依赖同上一轮本地固定2.4.21 jar，`PROVENANCE_GROOVY_JAR`可指定，SHA256=`de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0`，缺失/hash不符明确失败，不自动联网。全套测试会更新各来源生成证据，因此需要在隔离副本运行以保留原验收artifact；本轮isolated-regression.json保留该执行记录。
