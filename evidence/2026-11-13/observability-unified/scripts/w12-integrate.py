#!/usr/bin/env python3
# W12 per-plugin view wiring + hunk-level staged integration.
# Usage: w12-integrate.py <plugin-key> [--stage-only]
# Worktree edits are applied first (except --stage-only / kyverno), then the
# same plugin's hunks are applied to the index on top of HEAD (blob method),
# leaving Codex/other lines unstaged. Never touches the worktree files of
# registry/core/loki/loki-event (their wiring already lives in the worktree).
import subprocess, sys, os
REPO = os.path.expanduser('~/code/petclinic-platform-20261011')
MV = 'infra/security/manager-v2'
P = {
 'kyverno': dict(pid='kyverno'),
 'sonarqube': dict(pid='sonarqube', reg='realSonarRegistry', mod='sonar-real',
   helpers='sonarProjects,sonarReady,sonarBlockedReason,sonarUiCase', proj='sonarProjects',
   ready='sonarReady', blocked='sonarBlockedReason', ui='sonarUiCase', tool='7.2.0.5079',
   ident='security-sonar', timer=195000, polls=420, caps=['RUNTIME_TARGET','CREDENTIALS','TRUSTED_EXECUTOR'],
   subtitle='质量门禁 / 真实服务器分析', label='SonarQube · 质量门禁', runner='sonar-real',
   extras="gateStatus:f?.gateStatus??null,analysisId:f?.analysisId??null,componentKey:f?.componentKey??null,",
   exec='executeRealSonar', pred='realSonar'),
 'kubescape': dict(pid='kubescape', reg='realKubescapeRegistry', mod='kubescape-real',
   helpers='kubescapeProjects,kubescapeReady,kubescapeBlockedReason,kubescapeUiCase', proj='kubescapeProjects',
   ready='kubescapeReady', blocked='kubescapeBlockedReason', ui='kubescapeUiCase', tool='4.0.17',
   ident='security-kubescape', timer=1515000, polls=3300, caps=['CLUSTER_ACCESS','TRUSTED_EXECUTOR'],
   subtitle='集群姿态审计 / NSA·CIS 治理扫描', label='Kubescape · 集群姿态',
   extras="findings:f?.findings??null,failedControls:f?.failedControls??null,highRiskFindings:f?.highRiskFindings??null,auditDisposition:f?.auditDisposition??null,violating:f?.violating??null,",
   exec='executeRealKubescape', pred='realKubescape'),
 'zap': dict(pid='zap', reg='realZapRegistry', mod='zap-real',
   helpers='zapProjects,zapReady,zapBlockedReason,zapUiCase', proj='zapProjects',
   ready='zapReady', blocked='zapBlockedReason', ui='zapUiCase', tool='2.17.0',
   ident='security-zap', timer=255000, polls=540, caps=['RUNTIME_TARGET','TRUSTED_EXECUTOR'],
   subtitle='被动扫描 / 自建回环靶标', label='ZAP · 被动扫描',
   extras="policyLevel:level,alertsTotal:f?.alertsTotal??null,riskCounts:f?.riskCounts??null,reportSha256:f?.reportSha256??null,targetImage:f?.targetImage??null,",
   exec='executeRealZap', pred='realZap'),
 'provenance': dict(pid='provenance', reg='realProvenanceRegistry', mod='provenance-real',
   helpers='provenanceProjects,provenanceUiCase', proj='provenanceProjects',
   ready=None, blocked=None, ui='provenanceUiCase', tool=None,
   ident='local-operator', timer=45000, polls=190, caps=['PROVENANCE_METADATA','TRUSTED_EXECUTOR'],
   subtitle='来源声明验签 / 历史签名 DSSE 信封', label='Provenance · 来源声明',
   extras="subjectImage:f?.subjectImage??null,commit:f?.commit??null,buildNumber:f?.buildNumber??null,envelopeSha256:f?.envelopeSha256??null,",
   exec='executeRealProvenance', pred='realProvenance'),
 'build-provenance': dict(pid='build-provenance', reg='realBuildProvenanceRegistry', mod='build-provenance-real',
   helpers='buildProvenanceProjects,buildProvenanceUiCase', proj='buildProvenanceProjects',
   ready=None, blocked=None, ui='buildProvenanceUiCase', tool=None,
   ident='local-operator', timer=45000, polls=190, caps=['BUILD_METADATA','TRUSTED_EXECUTOR'],
   subtitle='构建来源核验 / 历史签名构建声明', label='Build Provenance · 构建来源',
   extras="subjectImage:f?.subjectImage??null,commit:f?.commit??null,buildNumber:f?.buildNumber??null,jarSha256:f?.jarSha256??null,envelopeSha256:f?.envelopeSha256??null,exitCode:f?.exitCode??null,",
   exec='executeRealBuildProvenance', pred='realBuildProvenance'),
 'sops': dict(pid='sops', reg='realSopsRegistry', mod='sops-real',
   helpers='sopsProjects,sopsReady,sopsBlockedReason,sopsUiCase', proj='sopsProjects',
   ready='sopsReady', blocked='sopsBlockedReason', ui='sopsUiCase', tool='3.13.3',
   ident='security-sops', timer=135000, polls=300, caps=['CREDENTIALS','TRUSTED_EXECUTOR'],
   subtitle='密钥门禁 / 文件夹具存储', label='SOPS · 密钥门禁',
   extras="storeModel:f?.storeModel??null,rbacModel:f?.rbacModel??null,cipherTargets:Array.isArray(f?.cipherFacts)?f.cipherFacts.length:null,",
   exec='executeRealSops', pred='realSops'),
}
def run(*a, inp=None):
    r = subprocess.run(a, cwd=REPO, input=inp, capture_output=True, text=True)
    if r.returncode: raise SystemExit(f'CMD FAIL {a}: {r.stderr[:400]}')
    return r.stdout
def read(rel): return open(os.path.join(REPO, rel)).read()
def write(rel, t): open(os.path.join(REPO, rel), 'w').write(t)
def rep(t, old, new, n=1):
    c = t.count(old)
    assert c == n, f'anchor count {c} != {n}: {old[:90]!r}'
    return t.replace(old, new)
def head(rel): return run('git', 'show', f'HEAD:{rel}')
def stage_blob(rel, text):
    h = run('git', 'hash-object', '-w', '--stdin', inp=text).strip()
    run('git', 'update-index', '--cacheinfo', f'100644,{h},{rel}')
def sync_line(head_t, work_t, anchor, startswith=None):
    wl = [l for l in work_t.split('\n') if anchor in l and (startswith is None or l.startswith(startswith))]
    hl = [i for i, l in enumerate(head_t.split('\n')) if anchor in l and (startswith is None or l.startswith(startswith))]
    assert len(wl) == 1 and len(hl) == 1, f'sync anchor {anchor!r}: work {len(wl)} head {len(hl)}'
    lines = head_t.split('\n'); lines[hl[0]] = wl[0]
    return '\n'.join(lines)

key = sys.argv[1]; s = P[key]; pid = s['pid']
stage_only = '--stage-only' in sys.argv or key == 'kyverno'
ACT = f'{MV}/view/actions.mjs'; APP = f'{MV}/view/app.js'; CTL = f'{MV}/view/controls.mjs'
REG = f'{MV}/registry.mjs'; CORE = f'{MV}/core.mjs'; LOKI = f'{MV}/consumers/loki.mjs'; LJ = f'{MV}/consumers/loki-event-v1.json'

# ---------- worktree edits (new plugins only) ----------
if not stage_only:
    a = read(ACT)
    a = rep(a, "} from '../registry.mjs';", f",{s['reg']}}} from '../registry.mjs';")
    kyv = [l for l in a.split('\n') if "from '../kyverno-real.mjs'" in l][0]
    a = rep(a, kyv, kyv + f"\nimport {{{s['helpers']}}} from '../{s['mod']}.mjs';")
    a = rep(a, "const ids=[", "const ids=[")  # noop guard
    il = [l for l in a.split('\n') if l.startswith('const ids=[')][0]
    a = rep(a, il, il.replace(']', f",'{pid}']", 1))
    # capabilities branch
    branch = None
    if s['ready']:
        branch = (f"pluginId==='{pid}'?{{pluginId,state:!enabled(pluginId)?'DISABLED':{s['ready']}()?'READY':'BLOCKED',"
          f"reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):{s['ready']}()?null:{s['blocked']}(),"
          f"runner:'{s.get('runner', pid + '-real')}',toolVersion:'{s['tool']}',toolVersionObservation:'PINNED',executionHost:'devops/192.168.1.58',"
          f"executionIdentity:'{s['ident']}',scenarios,projects:Object.entries({s['proj']}()).sort((a,b)=>Object.keys(b[1].cases??{{}}).length-Object.keys(a[1].cases??{{}}).length).map(([k])=>k)}}:")
    else:
        branch = (f"pluginId==='{pid}'?{{pluginId,state:!enabled(pluginId)?'DISABLED':'READY',"
          f"reason:!enabled(pluginId)?(control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED'):null,"
          f"runner:'{pid}-real',toolVersion:null,toolVersionObservation:'OFFLINE_DSSE_ARCHIVED_PROOF',executionHost:'local/offline',"
          f"executionIdentity:'local-operator',scenarios:['verified','rejected'],"
          f"projects:Object.entries({s['proj']}()).filter(([,p])=>Object.keys(p.cases??{{}}).length).map(([k])=>k)}}:")
    a = rep(a, "!enabled(pluginId)?{pluginId,state:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',configurationRevision",
              branch + "!enabled(pluginId)?{pluginId,state:'DISABLED',reason:control.settings.enabled?'PLUGIN_DISABLED':'MASTER_DISABLED',configurationRevision")
    # validateRequest
    if key in ('provenance',) :
        a = rep(a, "||!ids.includes(value.pluginId)||!scenarios.includes(value.scenarioId))throw fault('INVALID_FIXED_RUN_REQUEST');",
          "||!ids.includes(value.pluginId)||!(scenarios.includes(value.scenarioId)||['provenance','build-provenance'].includes(value.pluginId)&&['verified','rejected'].includes(value.scenarioId))||['provenance','build-provenance'].includes(value.pluginId)&&!['verified','rejected'].includes(value.scenarioId))throw fault('INVALID_FIXED_RUN_REQUEST');")
    a = rep(a, "||value.pluginId!=='sbom'&&", f"||value.pluginId==='{pid}'&&!{s['proj']}()[value.projectId]||value.pluginId!=='sbom'&&")
    a = rep(a, "&&value.projectId!==undefined)throw fault('PROJECT_NOT_AUTHORIZED',403);",
              f"&&value.pluginId!=='{pid}'&&value.projectId!==undefined)throw fault('PROJECT_NOT_AUTHORIZED',403);")
    # remote + timer
    if s['ready']:
        rl = [l for l in a.split('\n') if l.startswith(' const remote=value.pluginId===')][0]
        a = rep(a, rl, rl[:-1] + f"||value.pluginId==='{pid}'&&{s['ready']}();")
    a = rep(a, "value.pluginId==='sbom'?90000:30000", f"value.pluginId==='{pid}'?{s['timer']}:value.pluginId==='sbom'?90000:30000")
    # submit block
    caps = ','.join(f"{c}:{{state:'AVAILABLE'}}" for c in s['caps'])
    gate = f"run.gate['{pid}']" if '-' in pid else f"run.gate.{pid}"
    if key == 'zap':
        inputs = f"{{zap:{{targetId:cfg.targetId,caseId,policyLevel:level}}}}"
        pre = f"const cfg=zapProjects()[value.projectId],registry=realZapRegistry(),blocked=zapBlockedReason(),caseId=zapUiCase(cfg,value.scenarioId),level=value.scenarioId==='clean'?'standard':'strict';"
        cfgline = f"config:{{security:{{enabled:true,globalMode:'audit',securityLevel:level,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{{enabled:id==='zap'}}]))}}}}"
    elif s['ready']:
        inputs = f"{{{pid}:{{targetId:cfg.targetId,caseId}}}}"
        pre = f"const cfg={s['proj']}()[value.projectId],registry={s['reg']}(),blocked={s['blocked']}(),caseId={s['ui']}(cfg,value.scenarioId);"
        cfgline = f"config:{{security:{{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{{enabled:id==='{pid}'}}]))}}}}"
    else:
        inputs = f"{{'{pid}':{{targetId:cfg.targetId,caseId}}}}"
        pre = f"const cfg={s['proj']}()[value.projectId],registry={s['reg']}(),caseId={s['ui']}(cfg,value.scenarioId);"
        cfgline = f"config:{{security:{{enabled:true,globalMode:'audit',securityLevel:control.settings.securityLevel,profile:cfg.profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{{enabled:id==='{pid}'}}]))}}}}"
    host = "'devops/192.168.1.58'" if s['ready'] else "'local/offline'"
    toolv = f"'{s['tool']}'" if s['tool'] else 'null'
    blocked_part = ''
    if s['ready']:
        blocked_part = (f"if(blocked){{result={{...request,state:'BLOCKED',evidenceClass:'NOT_TESTED',reason:blocked,scannerExecuted:false,remoteInvocationCount:0,policyDecision:null,evaluationCount:0,resultDigest:null,artifactDigest:null,executionIdentity:'{s['ident']}',executionHost:{host},toolVersion:{toolv},caseId}};return;}}\n    ")
    block = (f"   if(value.pluginId==='{pid}'){{\n"
      f"    {pre}\n"
      f"    {blocked_part}attempted=true;\n"
      f"    const run=await runCandidate({{registry,runId,projectId:value.projectId,context:{{platform:process.platform,capabilities:{{{caps}}}}},inputs:{inputs},{cfgline},output:path.join(dir,'artifact'),signal:controller.signal}});\n"
      f"    const selected={gate},f=selected.runtimeFacts;\n"
      f"    const diagnostic=fs.existsSync(path.join(dir,'artifact/{pid}.execution-error.json'))?read(path.join(dir,'artifact/{pid}.execution-error.json')).diagnostic:null;\n"
      f"    fs.mkdirSync(path.join(dir,'router'),{{mode:0o700}});\n"
      f"    const routed=routeResults({{run,artifactDirectory:path.join(dir,'artifact'),expectedSealDigest:run.artifact.sealDigest,output:path.join(dir,'router'),definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')}});\n"
      f"    result={{...request,state:selected.executionStatus,evidenceClass:f?'REAL':'NOT_TESTED',scannerExecuted:!!f,policyDecision:selected.policyDecision,evaluationCount:selected.evaluationCount,resultDigest:selected.resultDigest,artifactDigest:run.artifact.sealDigest,source:path.relative(root,path.join(dir,'artifact/{pid}.result.json')),reason:selected.failureReason,\n"
      f"     executionDiagnostic:diagnostic,caseId,{s['extras']}toolVersion:f?.toolVersion??{toolv},toolSha256:f?.toolSha256??null,executionIdentity:'{s['ident']}',executionHost:{host},router:routed.receipts.map(r=>({{consumerId:r.consumerId,deliveryDecision:r.deliveryDecision}})),cleanup:selected.cleanup?.status??'NOT_VERIFIED'}};return;\n"
      f"   }}\n")
    a = rep(a, "   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');",
              block + "   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');")
    write(ACT, a)
    # app.js
    j = read(APP)
    j = rep(j, "}[p.pluginId],'plugin-sub'", f",'{pid}':'{s['subtitle']}'}}[p.pluginId],'plugin-sub'")
    detail = (f" if(r.pluginId==='{pid}'){{\n"
      f"  card.append(row('Project ID',r.projectId),row('Case',r.caseId),row('Result Router',(r.router??[]).map(x=>x.consumerId+': '+x.deliveryDecision).join(' / ')||'NOT_TESTED'),row('执行身份',r.executionIdentity),row('工具版本',r.toolVersion));\n"
      f" }}\n")
    j = rep(j, " if(r.pluginId==='cosign'&&r.scannerExecuted===true)", detail + " if(r.pluginId==='cosign'&&r.scannerExecuted===true)")
    varname = pid.replace('-', '') + 'Option'
    j = rep(j, "liveCapabilities=await api('/api/plugins');sessionToken=liveCapabilities.csrfToken;await refreshLive();",
      f"const {varname}=el('option','{s['label']}');{varname}.value='{pid}';$('live-plugin').append({varname});liveCapabilities=await api('/api/plugins');sessionToken=liveCapabilities.csrfToken;await refreshLive();")
    lines = j.split('\n')
    for i, l in enumerate(lines):
        if "/api/run',{method:'POST'" in l:
            assert l.rstrip().endswith('})});')
            lines[i] = l.rstrip()[:-5] + f",...($('live-plugin').value==='{pid}'?{{projectId:liveCapabilities?.plugins.find(p=>p.pluginId==='{pid}')?.projects?.[0]}}:{{}})" + '})});'
    j = '\n'.join(lines)
    j = rep(j, ':190;', f":$('live-plugin').value==='{pid}'?{s['polls']}:190;")
    if key == 'provenance':
        j = rep(j, "(id==='clean'?'Clean':'Controlled Finding')",
          "(c?.pluginId==='provenance'||c?.pluginId==='build-provenance'?(id==='verified'?'Verified':'Rejected'):id==='clean'?'Clean':'Controlled Finding')")
    # control lists: append pid to the three plugin lists
    import re as _re
    lists = _re.findall(r"\['gitleaks','semgrep','cosign','sbom','trivy'[^\]]*\]", j)
    assert len(lists) == 3, lists
    for L in set(lists):
        j = j.replace(L, L[:-1] + f",'{pid}']")
    write(APP, j)
    # controls.mjs
    c = read(CTL)
    cl = [l for l in c.split('\n') if l.startswith('export const managedPlugins=')][0]
    c = rep(c, cl, cl.replace(']', f",'{pid}']", 1))
    write(CTL, c)
    print('WORKTREE_EDITED', pid)

# ---------- staged applies ----------
work_a = read(ACT); work_j = read(APP)
# controls.mjs: worktree content == staged content
run('git', 'add', CTL)
# actions.mjs staged
h = head(ACT)
h = sync_line(h, work_a, "from '../registry.mjs';", startswith='import {realManagedRegistry')
if key != 'kyverno':
    kyv_h = [l for l in h.split('\n') if "from '../kyverno-real.mjs'" in l][0]
    newimp = [l for l in work_a.split('\n') if f"from '../{s['mod']}.mjs'" in l][0]
    h = rep(h, kyv_h, kyv_h + '\n' + newimp)
h = sync_line(h, work_a, 'const ids=[')
h = sync_line(h, work_a, 'plugins:ids.map(pluginId=>')
h = sync_line(h, work_a, 'export function validateRequest')
h = sync_line(h, work_a, 'const remote=value.pluginId===')
h = sync_line(h, work_a, 'const timer=setTimeout')
# submit block insertion (extract from worktree)
def extract_block(text, pidv):
    start = text.index(f"   if(value.pluginId==='{pidv}'){{")
    end = text.index("   if(process.platform!=='darwin'", start)
    return text[start:end]
blk = extract_block(work_a, pid)
h = rep(h, "   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');",
          blk + "   if(process.platform!=='darwin'||process.getuid()===0)throw fault('LOCAL_MAC_IDENTITY_REQUIRED');")
stage_blob(ACT, h)
# app.js staged
h = head(APP)
h = sync_line(h, work_j, "}[p.pluginId],'plugin-sub'")
def extract_detail(text, pidv):
    start = text.index(f" if(r.pluginId==='{pidv}'){{")
    end = text.index(" if(r.pluginId==='cosign'&&r.scannerExecuted===true)", start)
    return text[start:end]
det = extract_detail(work_j, pid)
h = rep(h, " if(r.pluginId==='cosign'&&r.scannerExecuted===true)",
          det + " if(r.pluginId==='cosign'&&r.scannerExecuted===true)")
for anchor in ["sbomOption=el('option'", "/api/run',{method:'POST'", 'const maxPolls=', "live-scenario').replaceChildren",
               "$('control-rows').replaceChildren", "$('effective-controls').textContent", "const settings={enabled:$('control-enabled')"]:
    h = sync_line(h, work_j, anchor)
stage_blob(APP, h)
print('STAGED_VIEW', pid)

if key in ('kubescape', 'zap', 'provenance', 'build-provenance', 'sops'):
    # registry.mjs staged
    h = head(REG); w = read(REG)
    predname = s['pred']
    # predicate line: take exact line from worktree
    pl = [l for l in w.split('\n') if l.strip().startswith(f'const {predname}=')][0]
    if key == 'kubescape':
        anchor = [l for l in h.split('\n') if l.strip().startswith('const realFalco=')][0]
        h = rep(h, anchor, anchor + '\n' + pl)
        h = rep(h, 'const real=realFalco||realSonar||', 'const real=realFalco||realSonar||realKubescape||')
        h = rep(h, 'realSonar?180000:30000', 'realSonar?180000:realKubescape?1500000:30000')
    elif key == 'zap':
        anchor = [l for l in h.split('\n') if l.strip().startswith('const realSonar=')][0]
        h = rep(h, anchor, anchor + '\n' + pl)
        h = rep(h, 'realKubescape||', 'realKubescape||realZap||')
        h = rep(h, 'realKubescape?1500000:30000', 'realKubescape?1500000:realZap?240000:30000')
    elif key == 'provenance':
        anchor = [l for l in h.split('\n') if l.strip().startswith('const realZap=')][0]
        h = rep(h, anchor, anchor + '\n' + pl)
        h = rep(h, 'realZap||', 'realZap||realProvenance||')
    elif key == 'build-provenance':
        anchor = [l for l in h.split('\n') if l.strip().startswith('const realProvenance=')][0]
        h = rep(h, anchor, anchor + '\n' + pl)
        h = rep(h, 'realProvenance||', 'realProvenance||realBuildProvenance||')
    elif key == 'sops':
        anchor = [l for l in h.split('\n') if l.strip().startswith('const realZap=')][0]
        h = rep(h, anchor, anchor + '\n' + pl)
        h = rep(h, 'realZap||', 'realZap||realSops||')
        h = rep(h, 'realZap?240000:30000', 'realZap?240000:realSops?120000:30000')
    # registry function (with preceding comment block) extracted from worktree
    wl = w.split('\n')
    fi = next(i for i, l in enumerate(wl) if l.startswith(f"export function {s['reg']}()"))
    ci = fi
    while ci - 1 >= 0 and wl[ci - 1].startswith('//'):
        ci -= 1
    if wl[ci - 1] == '' and ci - 2 >= 0 and wl[ci - 2] == '':
        pass
    fn_text = '\n'.join(wl[ci:fi + 1])
    h = h.rstrip('\n') + '\n\n' + fn_text + '\n'
    stage_blob(REG, h)
    # core.mjs staged
    h = head(CORE); w = read(CORE)
    imp = [l for l in w.split('\n') if f"from './{s['mod']}.mjs'" in l][0]
    anchor = [l for l in h.split('\n') if "from './sonar-real.mjs'" in l][0]
    h = rep(h, anchor, anchor + '\n' + imp)
    seg = f"p.runner==='{pid}-real'?await {s['exec']}(p,inputs[p.pluginId],{{signal,projectId,runId}}):"
    assert seg in w, 'dispatch segment missing in worktree'
    h = rep(h, ":await executeArchive(p,inputs[p.pluginId],{signal});", ':' + seg + "await executeArchive(p,inputs[p.pluginId],{signal});")
    stage_blob(CORE, h)
    print('STAGED_WIRING', pid)

# loki.mjs + loki-event-v1.json staged token inserts
h = head(LOKI)
WL = {
 'kyverno': ("'gitleaks','semgrep','cosign','sbom']", "'gitleaks','semgrep','cosign','sbom','kyverno']"),
 'sonarqube': ("'kyverno']", "'kyverno','sonarqube']"),
 'kubescape': ("'sonarqube']", "'sonarqube','kubescape']"),
 'zap': ("'kubescape']", "'kubescape','zap']"),
 'provenance': ("'zap']", "'zap','provenance']"),
 'build-provenance': ("'zap','provenance']", "'zap','provenance','build-provenance']"),
 'sops': ("'zap','provenance'", "'zap','sops','provenance'"),
}[key]
h = rep(h, WL[0], WL[1])
if key == 'provenance':
    h = rep(h, "if(['cosign','sbom'].includes(r.pluginId))", "if(['cosign','sbom','provenance'].includes(r.pluginId))")
if key == 'build-provenance':
    h = rep(h, "if(['cosign','sbom','provenance'].includes(r.pluginId))", "if(['cosign','sbom','provenance','build-provenance'].includes(r.pluginId))")
stage_blob(LOKI, h)
print('STAGED_LOKI', pid)

h = head(LJ)
if key == 'kubescape':
    h = rep(h, '"kyverno", "falco"', '"kubescape", "kyverno", "falco"')
elif key == 'zap':
    h = rep(h, '"sonarqube", "manager"', '"sonarqube", "zap", "manager"')
elif key == 'provenance':
    h = rep(h, '"zap", "manager"', '"zap", "provenance", "manager"')
elif key == 'build-provenance':
    h = rep(h, '"provenance", "manager"', '"provenance", "build-provenance", "manager"')
elif key == 'sops':
    h = rep(h, '"manager"]', '"manager", "sops"]')
if key in ('kubescape', 'zap', 'provenance', 'build-provenance', 'sops'):
    stage_blob(LJ, h)
    print('STAGED_LOKIEVENT', pid)
print('INTEGRATE_DONE', pid)
