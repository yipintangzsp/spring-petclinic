"""Offline final acceptance and audit index. No API, credential or Gate execution."""
from pathlib import Path
import json,hashlib,datetime
R=Path.cwd();O=R/'evidence/2026-11-02/sops-authoritative-differential-02';P=R/'evidence/2026-11-02/sops-authoritative-baseline-02'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(n,x):(O/n).write_text(json.dumps(x,indent=2))
A=json.loads((O/'precleanup-acceptance.json').read_text());C=json.loads((O/'cleanup-result.json').read_text());B=json.loads((P/'authoritative-baseline.json').read_text());T=json.loads((O/'token-refresh.json').read_text());X=json.loads((O/'precleanup-evidence-index.json').read_text())
assert A['status']=='PASS' and C['status']=='COMPLETE' and A['matches']==12 and A['drifts']==0
assert len([x for x in C['operations'] if x.get('absent')])==23
assert any(x.get('httpStatus')==401 for x in C['operations'])
assert not Path(B['root']).exists()
for n,h in X['files'].items():assert (O/n).is_file() and sha(O/n)==h
assert sha(P/'authoritative-baseline.json')==X['baseline']['sha256']
before=json.loads((O/'project-before.json').read_text());assert all((R/n).is_file() and sha(R/n)==h for n,h in before.items())
host=json.loads((O/'protected-before.json').read_text());assert all(sha(Path(x['path']))==x['sha256'] for x in host)
for n,h in B['frozenSourceSha256'].items():assert sha(R/n)==h
node=Path('/private/tmp/sm-node-executor-erg_cakg/runtime/bin/node');assert sha(node)=='d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d'
for e in A['cases']:
 doc=json.loads((O/e['executionEvidence']).read_text());events=doc['result']['rawEvidence']['events'];observed=[x['sha256'] for x in events if x['kind']=='TOOL_SHA_READ']
 if e['scenario'] not in ('TOOL_MISSING','LEASE_HOLDER_MISMATCH'):assert observed==['53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77']
 else:assert observed==[]
dump('protected-final-validation.json',{'status':'PASS','preExistingProjectFilesUnchanged':len(before),'hostConfigFilesUnchanged':len(host),'baselineUnchanged':True,'gateUnchanged':True,'scannerRuntimeUnchanged':True,'adapterUnchanged':True,'policyBaselineUnchanged':True,'securitySummaryUnchanged':True,'noRollout':True,'productionApiAccess':0,'productionSecretCredentialReads':0,'productionAgeKeyReads':0,'nodeSha256':sha(node),'sopsRuntimeToolHashObservedInAll10CasesReachingSuccessfulVerifyTools':True,'leaseMismatchStopsBeforeVerifyToolsAsFrozenSourceRequires':True,'auditCorrection':'Initial final-audit assertion incorrectly expected a SOPS read after failed requireLease. Corrected audit-only assertion to the actual frozen source order. No Gate decision/evidence/expectation modified.'})
dump('compatibility-verdict.json',{'SOPS_COMPATIBILITY':'VERIFIED','scope':'Approved 12 frozen production-logic scenarios, REAL_CONTROLLED_EXECUTION in isolated kind; not historical production incidents, not whole Policy Engine verification','approved':12,'applicable':12,'notApplicable':0,'oldGateExecutions':12,'adapterPolicyExecutions':12,'matches':12,'drifts':0,'oldDecisionDistribution':{'PASS':1,'FAIL':11},'policyDecisionDistribution':{'PASS':1,'FAIL':11},'semanticBaselineRestoredBeforeCleanup':True,'originalUidIdenticalBeforeCleanup':False,'cleanup':'COMPLETE','historicalNegativeEvidence':'DEFERRED','summaryIntegrationAuthorized':False,'nextAction':'STOP. Review evidence; any subsequent production-coverage audit or Summary work requires its own scope.'})
local=lambda epoch:datetime.datetime.fromtimestamp(epoch,datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S +08:00')
items=[
 ('refreshed token identity/lifetime',T['sameSA']+'；相同 SA UID；3600s；'+local(T['iat'])+' → '+local(T['exp'])+'；清理后已失效'),
 ('real SA authentication result','PASS：host guard 与真实 Linux MIN_RBAC guard 均严格 TLS / CA / namespace UID / SelfSubjectReview 验证，无 admin fallback'),
 ('27/27 authorization recheck','PASS；RBAC_DENIED 恢复后再验 27/27 PASS'),
 ('guard sanity result','5/5 PASS（sanity 是单元检查；真实认证另有独立证据）'),
 ('authoritative baseline precheck','MATCHED：23 个原 UID/完整 snapshot SHA、加密文件、工具及冻结源码匹配；仅预期 token 轮换'),
 ('total approved scenarios','12'),('applicable scenarios','12'),('NOT_APPLICABLE scenarios','0；Secret type 的比较由 secrets-gate.mjs:21 明确执行'),
 ('old Gate executions','12；冻结 Gate 源文件未修改；观察器透传真实调用、参数、stdin 和结果'),
 ('adapter/Policy executions','12；existing SOPS adapter + baseline-v1 / standard'),
 ('oldDecision distribution','PASS=1；FAIL=11'),('policyDecision distribution','PASS=1；FAIL=11'),('total MATCH','12'),('total DRIFT','0'),
 ('POSITIVE_FULL_PATH result','PASS = PASS；4 个 Secret 的真实 decrypt/read/apply/read、UID/值保留及 13 项 Gate RBAC 检查通过'),
 ('WRONG_AGE_KEY result','FAIL = FAIL；真实 SOPS exit=128；stdout=0 bytes；无 fallback key'),
 ('DECRYPT_ERROR result','FAIL = FAIL；单字符密文破坏；真实 SOPS exit=25；stdout=0 bytes；与 wrong-key 区分'),
 ('SECRET_MISSING result','FAIL = FAIL；真实 Secret 删除/读取失败；按新 UID 重建并留恢复收据'),
 ('SECRET_TYPE_MISMATCH result','FAIL = FAIL；真实类型改为 basic-auth；冻结 Gate 的 data/type 比较拒绝'),
 ('SECRET_DATA_MISMATCH result','FAIL = FAIL；真实 synthetic 值变更；仅归档 before/after 指纹'),
 ('UID_CONTINUITY_FAILURE result','FAIL = FAIL；真实 apply 后删除/重建；实际 UID 不同而值指纹相同'),
 ('VALUE_PRESERVATION_FAILURE result','FAIL = FAIL；真实 apply 后改值；实际 UID 相同而值指纹不同'),
 ('LEASE_HOLDER_MISMATCH result','FAIL = FAIL；真实 Lease holder 不匹配；随后恢复原 spec'),
 ('RBAC_DENIED result','FAIL = FAIL；仅从测试 reconciler Role 移除 get；真实受限凭据读取失败；恢复规则与 27 项授权'),
 ('TOOL_MISSING result','FAIL = FAIL；仅临时 executor 缺 SOPS；真实 ENOENT；全局工具未改'),
 ('REPORT_WRITE_FAILURE result','FAIL = FAIL；临时输出位置为目录；真实 EISDIR；未改生产目录权限'),
 ('raw-fact preservation result','PASS；每例 evaluate 前后原始内存事实相同；证据含输出字节数/SHA、UID/值指纹、exit/signal/timeout；无新增 severity'),
 ('restoration/contamination result','PASS：每例 23 对象语义和所需当前 UID 均核验；原 petclinic-db UID 经 4 次预期替换，原 baseline 未覆盖；不宣称 UID/字节完全恢复'),
 ('evidence-index validation','PASS；precleanup 与 final 索引逐文件存在性/SHA 验证；matrix/cleanup 请求计数分开版本化'),
 ('fixture cleanup','COMPLETE：23 个受控对象删除、两个 age 私钥及 token/kubeconfig 删除、临时 executor/私有目录无残留；旧 token HTTP 401；kind 保留'),
 ('production API access count','0'),('production Secret/credential reads','0'),('production age-key reads','0'),('production files modified YES/NO','NO；4113 个既存项目文件 SHA 均保持一致'),('Gate modified YES/NO','NO；scanner-runtime、adapter 同样未改'),('Policy baseline modified YES/NO','NO'),('Summary modified YES/NO','NO'),
 ('SOPS_COMPATIBILITY','VERIFIED — 仅本轮批准的冻结生产逻辑受控执行兼容性范围'),
 ('exact first drift/blocker if not VERIFIED','无语义 drift 或剩余 blocker。执行前曾遇基础镜像默认 init 入口错误，显式指定 Python 后完成；未修改 Gate/adapter/Policy'),
 ('exact next permitted action if VERIFIED','STOP。供下一轮复核全生产 Gate coverage；本轮不接 Summary、不启动统一插件契约或其他来源')]
assert len(items)==40
text='SOPS_COMPATIBILITY = VERIFIED\n\n范围：隔离 kind 中 12 项 REAL_CONTROLLED_EXECUTION；不是生产事故历史，也不代表整个 Policy Engine 已通过。\n\n'
text+='\n'.join(f'{i}. **{name}**：{value}' for i,(name,value) in enumerate(items,1))
text+='\n\n证据入口：compatibility-verdict.json、precleanup-acceptance.json、final-evidence-index.json、final-index-validation.json。\n\n事实与差分：每例 *-execution.json；恢复：每例 *-restoration-receipt.json；原基线：../sops-authoritative-baseline-02/authoritative-baseline.json（原始内容保留）。\n\n观察边界：不把期望判定写入 raw fact；Node preload 仅透传观测与受控竞态屏障。decrypted stdout/data 仅在内存中传给原 Gate 与 adapter，归档只保留指纹/相等性；不归档 stderr 内容。初次入口错误保留于 pre-execution-entrypoint-error.json。\n\n审计注：cleanup 与 matrix 复用了管理脚本的 request-count 文件名，已将 cleanup 计数另存；matrix snapshot 以原索引 SHA 逐字节核对恢复，详见 request-counter-version-receipt.json。未修改任何 Gate 决策证据。\n'
(O/'REPORT.md').write_text(text)
files={str(p.relative_to(O)):sha(p) for p in O.rglob('*') if p.is_file() and p.name not in ['final-evidence-index.json','final-index-validation.json']}
dump('final-evidence-index.json',{'status':'FINAL','files':files,'cases':A['cases'],'baselineReference':X['baseline'],'frozenSources':B['frozenSourceSha256'],'tools':B['toolchain'],'node':B['nodeRuntime'],'summaryIntegration':False})
for n,h in files.items():assert (O/n).is_file() and sha(O/n)==h
for entry in A['cases']:
 for n,h in entry['evidenceFiles'].items():assert sha(O/n)==h
dump('final-index-validation.json',{'status':'PASS','filesChecked':len(files),'allReferencesExist':True,'allSha256Match':True,'nestedPrecleanupIndexValid':True,'caseIndexValid':True,'originalBaselineReferenceValid':True,'indexSha256':sha(O/'final-evidence-index.json'),'cleanupComplete':True,'SOPS_COMPATIBILITY':'VERIFIED'})
print('SOPS_COMPATIBILITY = VERIFIED; FINAL_INDEX_PASS; STOP')
print('filesChecked',len(files))
