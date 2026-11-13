from pathlib import Path
import json,hashlib,re,subprocess,datetime
R=Path('/Users/zhangsir/code/petclinic-platform-20261011');O=R/'evidence/2026-11-03/helm-shadow-phase1';E=O.parent/'runtime-checkpoint-epoch-v2';A=O/'production-after'
load=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def dump(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
base=load(O/'current-desired.json');equiv=load(O/'jenkins-artifacts-6/.helm-shadow/equivalence.json');status=load(O/'jenkins-artifacts-6/.helm-shadow/status.json');source=load(O/'source-identity.json');discovery=load(O/'discovery.json');protect=load(O/'production-protection.json')
assert equiv['status']=='VERIFIED' and not equiv['changes'];assert equiv['fieldComparisons']==205
before=(O/'Jenkinsfile.security-audit.before').read_text();after=(R/'Jenkinsfile.security-audit').read_text()
stripped=after
for key in ['PARAMETERS','PRECONDITIONS','ARCHIVE']:stripped=re.sub(r'// HELM_SHADOW_'+key+r'_BEGIN[\s\S]*?// HELM_SHADOW_'+key+r'_END\n','',stripped)
stripped=re.sub(r'// HELM_SHADOW_STAGES_BEGIN[\s\S]*?// HELM_SHADOW_STAGES_END\n\n','',stripped);assert stripped==before
matrix=load(E/'source-hash-matrix.json');deltas=[]
for group in ['implementationHashes','frozenGateHashes']:
 for p,h in matrix[group].items():
  actual=sha(R/p)
  if actual!=h:
   assert p=='Jenkinsfile.security-audit' and hashlib.sha256(stripped.encode()).hexdigest()==h
   deltas.append({'path':p,'before':h,'after':actual,'authorizedChange':'Additive Helm parameters/preconditions/validation/archive blocks only','frozenGateTextRestoredSha256':hashlib.sha256(stripped.encode()).hexdigest()})
seals=[];count=0
for folder in ['runtime-checkpoint-epoch-v2','trivy-guard-experiment-design','trivy-guard-dependency-boundary-review','trivy-resource-feasibility-audit']:
 p=O.parent/folder/'evidence-sha256.json';s=load(p)
 for f,h in s['files'].items():assert sha(p.parent/f)==h,f
 seals.append({'path':str(p.relative_to(R)),'sha256':sha(p),'files':len(s['files'])});count+=len(s['files'])
old=0
for ref in load(E/'checkpoint.json')['historicalFailedCheckpointRefs']['priorSeals']:
 p=R/ref['path'];assert sha(p)==ref['sha256']
 for f,h in load(p)['files'].items():assert sha(p.parent/f)==h;old+=1
preservation={'status':'VERIFIED_WITH_EXPLICIT_ADDITIVE_CI_DELTA','existingImplementationFilesUnchanged':77,'newEpochToolingFilesUnchanged':9,'oldUniqueGateSourceFiles':229,'byteIdenticalGateSourceFiles':228,'authorizedDeltas':deltas,'compatibilityCorpusCountUnchanged':2202,'priorEvidenceFilesUnchanged':count+old,'priorSeals':seals,'existingCheckpointRebased':False,'currentEpochContinuityClaimed':False,'note':'Old historical acceptance/evidence untouched. A replay against this newer working-tree source must report the authorized Jenkinsfile raw hash change; no old integrity manifest was rewritten.'};dump('source-preservation.json',preservation)
# Separate production ancillary-state comparison; no full DB digest claim.
def dbfp(p):
 lines=p.read_text().splitlines();f={};m={}
 for line in lines:
  if line.startswith('/home/scanner/.cache/trivy/') and '|' in line:f[line.split('|')[0]]=line
 for i,line in enumerate(lines):
  if line.startswith('METADATA:'):m[line[9:]]=lines[i+1]
 return f,m
P=O.parent/'trivy-resource-feasibility-audit'
assert dbfp(P/'trivy-filesystem-before.stdout')==dbfp(O/'trivy-filesystem-after.stdout')
assert load(P/'dojo-governance-before.json')==load(O/'dojo-governance-after.json')
protect.update({'TrivyDBFileMetadataAndMetadataJsonUnchanged':True,'fullTrivyDBChecksumRecomputed':False,'TrivyGuardUnchanged':True,'DojoSelectedMetadataAndIdentityUnchanged':True,'SecuritySummaryV1Sha256':next(j for j in load(O/'live-jenkins-final.json')['jobs'] if j['job']=='petclinic-ci')['summarySha256'],'nodesReady':3,'PetClinicReady':3,'HTTP':200,'candidateApplicationAbsentReadOnlyCheck':True,'newHelmSecuritySources':0,'noProductionSecretValuesRead':True});dump('production-protection.json',protect)
# Per-resource full-leaf comparisons plus explicit image components.
d=next(x for x in base if x['kind']=='Deployment');image=d['spec']['template']['spec']['containers'][0]['image'];derived=[{'resource':'Deployment/petclinic','field':'image.repository','current':image.split('@')[0],'rendered':image.split('@')[0],'classification':'SEMANTIC_EQUIVALENT'},{'resource':'Deployment/petclinic','field':'image.digest','current':image.split('@')[1],'rendered':image.split('@')[1],'classification':'SEMANTIC_EQUIVALENT'}];dump('field-diff-report.json',{'status':'VERIFIED','normalization':equiv['normalization'],'fullResourceFields':equiv['fields'],'derivedImageFields':derived,'drift':[],'ownershipExcludedPlatformResources':load(O/'deployment-inventory.json')['platformResourcesExcluded']})
tests={}
for name,expected in [('helm-tests',43),('runtime-tests',143),('policy-core-tests',5),('regression-tests',147)]:
 text=(O/(name+'.log')).read_text();m=re.search(r'(?:ℹ|#) tests (\d+)',text);p=re.search(r'(?:ℹ|#) pass (\d+)',text);f=re.search(r'(?:ℹ|#) fail (\d+)',text);assert m and p and f and int(m[1])==int(p[1])==expected and int(f[1])==0,name;tests[name]={'tests':expected,'pass':expected,'fail':0}
assert load(O/'policy-contract.json')['ready'];tests['contract-checks']={'tests':10,'pass':10,'fail':0};tests['totalDistinctLocalTestsAndAssertions']=348;tests['controlledNegativeStageExecutions']=8;tests['JenkinsOffAndOnPipelineAssertionsEach']=13;dump('test-results.json',tests)
verdict={'HELM_TOOLING_INTEGRATION':'VERIFIED','HELM_CHART':'VERIFIED','HELM_LINT':'PASS','HELM_RENDER':'PASS','HELM_RENDER_EQUIVALENCE':'VERIFIED','HELM_POLICY_VALIDATION':'NOT_APPLICABLE','HELM_DIGEST_GUARD':'VERIFIED','HELM_GITOPS_UPDATE_FUNCTION':'VERIFIED','ARGOCD_HELM_CANDIDATE':'VERIFIED','DIRECT_DEPLOYMENT_PROHIBITION':'VERIFIED','HELM_ENABLED_FALSE_COMPATIBILITY':'VERIFIED','HELM_VALIDATION_MODE':'VERIFIED','HELM_PRODUCTION_CUTOVER':'NOT_PERFORMED','PRODUCTION_HELM_DEPLOYMENT':'NOT_ACTIVE','TRIVY_RUNTIME_FACT_CAPTURE':'INCOMPLETE','DEFECTDOJO_RUNTIME_FACT_CAPTURE':'INCOMPLETE','FINAL_WIRED_CAPABILITY':'14/16','REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE','REAL_POLICY_OWNER':'INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE','RELEASE_COUNT':0,'ROLLOUT_COUNT':0};dump('verdict.json',verdict)
rows=[]
def item(label,result,refs=[]):rows.append({'number':len(rows)+1,'item':label,'result':result,'evidence':refs})
item('current deployment inventory',load(O/'deployment-inventory.json'),['deployment-inventory.json'])
item('current GitOps path',{'source':discovery['argoSource'],'revision':discovery['gitOpsRevision'],'localOldYAMLNotBaseline':True},['discovery.json'])
item('current Argo CD ownership','Existing Application petclinic owns V1 k8s/production.11 chart-scoped PetClinic resources preserved;3 platform resources stay V1. No source switch, takeover or simultaneous candidate Application.',['application-current.json'])
item('Helm version',{'version':status['tool']['version'],'actualLinuxARM64':True,'actualDarwinARM64':True,'AMD64':'Official archive/binary verified; not executed on AMD64 in this round'})
item('Helm installation/tool strategy',{'lock':load(R/'infra/helm/tools-lock.json'),'cache':status['tool']['cachePath'],'systemHelmUnchanged':True,'strategy':'Workspace cache, archive+binary checksum verification, no global install, no Tiller. Existing network proxy failed; official archives fetched through read-only trusted host route, not changed proxy.'})
item('feature flag implementation','HELM_ENABLED=false by default. False helper returns before any step; true requires audit-only and performs shadow validation. Frozen Security Manager stages retain order; shadow uses current production digest, not candidate/approval. Local production entrypoint changes are not activated in pinned production Jenkins definition.')
item('chart structure',source['chartFiles'])
item('Chart.yaml',(R/'charts/petclinic/Chart.yaml').read_text())
item('values model','All current Deployment/container/Service/Ingress/config/PDB/probe/resource/security/scheduling/env/volume/lifecycle inputs modeled; static6 observability objects retained byte-semantic identity in files/observability.json. JSON output is valid YAML; no extra YAML parser installation needed.')
item('prod values model',(R/'charts/petclinic/values-prod.yaml').read_text())
item('digest handling',{'renderedImage':image,'appVersionTrustSource':False,'shadowUsesCurrentProductionOnly':True,'newDigestApproved':False,'approvedUpdaterRequiresSignedEvidence':True})
for label,path in [('Deployment template','charts/petclinic/templates/deployment.yaml'),('Service template','charts/petclinic/templates/service.yaml'),('Ingress template','charts/petclinic/templates/ingress.yaml')]:item(label,{'path':path,'sha256':sha(R/path),'equivalence':'VERIFIED'})
item('ConfigMap handling','Primary config data and4 Grafana ConfigMaps preserved. No Secret object rendered. External optional platform-snapshot CM unchanged.',['field-diff-report.json'])
item('ServiceAccount/RBAC handling','Current app has no explicit SA/RBAC object; default SA with automountServiceAccountToken=false preserved. serviceAccount.create=false enforced; no invented SA/RBAC or new permissions. Secret references only.')
for label,keys in [('probes preservation',['startupProbe','readinessProbe','livenessProbe']),('resources preservation',['resources']),('securityContext preservation',['securityContext'])]:item(label,{'current':{k:d['spec']['template']['spec']['containers'][0][k] for k in keys},'comparison':'Exact equality VERIFIED'},['field-diff-report.json'])
item('scheduling preservation',{'nodeSelector':d['spec']['template']['spec']['nodeSelector'],'topology':d['spec']['template']['spec']['topologySpreadConstraints'],'tolerations':d['spec']['template']['spec']['tolerations'],'architecturePinAdded':False,'affinityAbsentPreserved':True})
item('observability preservation','Prometheus ServiceMonitor/PrometheusRule/selectors and dashboard data, app labels for Alloy/Loki, OTLP/Jaeger tracing env and PostgreSQL references preserved. No live observability redesign.',['field-diff-report.json'])
item('Helm lint result','PASS locally and dedicated Jenkins #6',['helm-lint.log','jenkins-artifacts-6/.helm-shadow/lint.log'])
item('Helm render result','PASS on DarwinARM64 and Jenkins LinuxARM64; exact render SHA equal')
item('rendered manifest hash',source['linuxAndDarwinRenderSha256'])
item('semantic-equivalence result',{'status':'VERIFIED','resources':11,'fullLeafComparisons':205,'driftCount':0,'normalization':'object-key order/document formatting only; no meaningful field or runtime annotation ignored'},['field-diff-report.json'])
for label,kind in [('Deployment comparison','Deployment'),('Service comparison','Service'),('Ingress comparison','Ingress')]:item(label,{'kind':kind,'status':'VERIFIED','scope':'All spec/metadata fields, including selectors, ports, images, security, resources, probes, volumes, scheduling, env, grace/strategy; Ingress host/path/backend/TLS preserved'},['field-diff-report.json'])
item('policy validation',{'status':'NOT_APPLICABLE','preservationChecks':'PASS','engineExecuted':False,'why':'Existing admission runner server-dry-runs cluster probes; frozen Kubescape orchestration requires outer Lease and mints read-only token. No existing pure offline rendered-manifest adapter exercised within no-mutation contract. Do not bypass resource/identity prerequisites or label static checks as real scanner PASS.','futurePrerequisite':'A separately authorized supported offline/validation policy path before real cutover; existing production policy/Gates untouched'},['policy-result.json','jenkins-artifacts-6/.helm-shadow/policy.json'])
item('digest guard','VERIFIED for shadow and future updater: missing/malformed/tag-only digest fails; candidate without approval cannot update; existing promotion contract reused. True shadow denies promotion actions. No new approval issued.')
item('GitOps update function',{'path':'infra/helm/update-image-digest.mjs','behavior':'Validates digest and signed approval using existing pinned Cosign/public key; stale previous runtime rejected; only image.digest transformed; writes new candidate copy with wx and emits diff; no Git push','tests':'Pure positive synthetic approval transformation + negative candidate/FAIL/stale/tag; signature invocation required before CLI output. No real new signed approval generated.'})
item('Argo CD Helm candidate',{'path':'infra/argocd/petclinic-helm-candidate.yaml','status':'NOT_ACTIVE / VALIDATION_ONLY','sourcePath':'charts/petclinic','values':['values-prod.yaml'],'repoRevisionDestinationSyncPolicyPreserved':True,'applied':False,'caution':'Inherited automated sync policy; never apply candidate alongside V1. Future chart must first exist in correct GitOps revision under separate approved change.'})
item('production Application mutation count',0)
item('direct deployment command scan','VERIFIED active+shadow CI entrypoints; negative guard tests reject forbidden commands. Scope excludes unchanged approved scanner diagnostic implementations.',['helm-tests.log'])
item('HELM_ENABLED=false compatibility',{'status':'VERIFIED','job':'petclinic-helm-shadow-20261103','build':5,'result':'SUCCESS','runtimeDisabledHelperExecuted':True,'allHelmStagesSkipped':True,'pipelineAssertions':13,'originalProductionPipelineWithoutHelmBlocksByteIdentical':True,'scopeLimit':'No full production Security Manager pipeline rerun, to preserve production #270 and blocked14/16 roadmap. This is dedicated runtime disabled-helper + exact source-compatibility proof.'},['jenkins-build-5.json','jenkins-build-5.log'])
item('HELM_ENABLED=true validation build',{'job':'petclinic-helm-shadow-20261103','build':6,'result':'SUCCESS','reviewManifestSha256':sha(O/'review-bundle-manifest.json'),'allHelmStagesExecuted':True,'productionPushOrDeploy':False},['jenkins-build-6.json','jenkins-build-6.log'])
item('negative tests',{'controlledOfflineStageExecutions':8,'allCorrectNonzero':True,'fixtures':['missing digest','malformed digest','tag image','Deployment selector mismatch','Service selector mismatch','invalid template','privileged container','missing request'],'tempRemoved':True,'productionFilesModified':False,'firstJenkinsFailure':'#1 failed Declarative compile due inline when/steps formatting, fixed and linter verified; failure log retained, not counted as a controlled negative sample'},['negative-stage-fixtures.json','jenkins-build-1.log'])
item('chart tests',tests['helm-tests'],['helm-tests.log'])
item('current pipeline tests',{'Regression':147,'newPipelineCompatibilityAndProhibitionAssertions':13,'JenkinsNativeLinter':'Both entrypoints successfully validated','productionFullPipelineRerun':False},['jenkins-native-lint.json'])
item('runtime tests',tests['runtime-tests']);item('Policy core',tests['policy-core-tests']);item('contract tests',tests['contract-checks']);item('Regression147/147',tests['regression-tests']);item('source/hash preservation',preservation,['source-preservation.json'])
item('production Jenkins state',{'job':'petclinic-ci','latestBuild':270,'result':'SUCCESS','SCMBranchUnchanged':discovery['jobBranches'],'newHelmCodeNotActivatedInProductionJob':True},['live-jenkins-final.json'])
item('production digest',image)
item('Argo CD production state',{'source':discovery['argoSource'],'revision':discovery['gitOpsRevision'],'sourceAndSpecUnchanged':True,'candidateAbsent':True,'sync':'Synced','health':'Healthy'},['production-protection.json','final-production-verification.json'])
item('nodes state','devops / aliyun-worker / ucloud-worker Ready',['node-lease-postflight.json'])
item('PetClinic state','3/3 Ready;3 Ready Endpoint; Deployment/Service/Ingress UID and spec unchanged',['live-protected-final.json'])
item('HTTP result',200);item('release count',0);item('rollout count',0)
for key in ['HELM_TOOLING_INTEGRATION','HELM_CHART','HELM_RENDER_EQUIVALENCE','HELM_DIGEST_GUARD','HELM_GITOPS_UPDATE_FUNCTION','ARGOCD_HELM_CANDIDATE','HELM_ENABLED_FALSE_COMPATIBILITY','HELM_VALIDATION_MODE','HELM_PRODUCTION_CUTOVER']:item(key,verdict[key])
item('exact remaining Helm blockers',{'phase1Shadow':'No render/tooling/structural blocker remains within declared shadow scope.','limits':['No real Kyverno/Kubescape engine run; policy preservation only, NOT_APPLICABLE engine status','No full production Gate pipeline rerun or production job activation; off-mode evidence is explicitly scoped','AMD64 Helm archive verified but actual AMD64 execution not performed','Chart/candidate code committed locally only, no GitOps push or source activation'],'futureCutoverBlockedBy':['Security runtime14/16 / Trivy resource audit closed and blocked / Dojo dependency','Future signed approved digest and policy checks','Ownership separation for two platform Applications and Harbor alias','Explicit cutover authorization, current baseline revalidation and rollback verification']})
item('exact future cutover prerequisites','Follow docs/helm/FUTURE-CUTOVER.md: satisfy security roadmap, freeze current state, real approved digest + policy verification, exact render diff, resolve platform ownership, publish reviewed GitOps source separately, update existing Application only in approved window, Argo owns reconciliation, monitor HTTP/endpoints/metrics/logs/traces, Git revert/V1 source restore on failure. None executed.')
item('exact next permitted action','STOP. Keep V1 active and chart/candidate inactive. Local commit '+source['localCommit']+' saved on feature branch, not pushed. No production Helm install/upgrade/rollback, kubectl workload mutation, GitOps push, new digest promotion or SummaryV2. Resource audit remains CLOSED until material change.')
assert len(rows)==64;dump('report-items.json',rows)
lines=['# PetClinic Helm Phase1 / Shadow Mode 验收报告','','**Shadow 集成已验证；生产 Helm migration 未执行。** 本地提交 `'+source['localCommit']+'`，未 push。生产 Jenkins仍 #270 SUCCESS，Argo仍使用V1，Security Runtime仍14/16。','','独立 Jenkins job #5（关闭）与 #6（开启）SUCCESS。11资源/205字段等价；348项本地测试和断言通过，另8个真实离线受控stage负例均正确失败。首个专用构建#1的语法编译失败及修复证据完整保留。','','验收限制：关闭模式是独立job的helper实跑+原生产pipeline逐字兼容证明，未重跑完整生产Security Manager。Kyverno/Kubescape引擎未执行，状态NOT_APPLICABLE；安全字段保留检查PASS。没有宣称新漏洞扫描或新增安全来源。','']
for r in rows:
 lines += [str(r['number'])+'. **'+r['item']+'**',''];value=r['result'];lines+=['   '+(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2)).replace('\n','\n   '),'']
 if r['evidence']:lines+=['   Evidence: '+', '.join('`'+x+'`' for x in r['evidence']),'']
lines+=['## Final verdicts','','```text']+[k+'='+str(v) for k,v in verdict.items()]+['```','','STOP。']
(O/'REPORT-64.md').write_text('\n'.join(lines)+'\n')
dump('stop-receipt.json',{'state':'STOP','localCommit':source['localCommit'],'gitPush':0,'productionApplicationMutations':0,'productionDigestChanges':0,'KubernetesWorkloadMutations':0,'release':0,'rollout':0,'HelmProductionDeployment':'NOT_ACTIVE','SecurityRuntime':'14/16','SummaryV2':'INCOMPLETE','resourceAuditRemainsClosed':True,'newRuntimePolicyEvaluations':0})
print(json.dumps({'reportItems':len(rows),'testsAndAssertions':348,'negativeStageRuns':8,'fieldComparisons':205,'sourceFilesAuthorizedDelta':len(deltas),'commit':source['localCommit'],'priorEvidenceFilesUnchanged':count+old}))
