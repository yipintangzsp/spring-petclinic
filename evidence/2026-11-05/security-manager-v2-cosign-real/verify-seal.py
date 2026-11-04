"""This round's seal and historical metadata preservation. Never upgrades old FAILED."""
from pathlib import Path
import sys,json,hashlib,stat,subprocess
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=json.loads((OUT/'protected-before.json').read_text());changes=[]
for n,old in base['protected'].items():
 p=ROOT/n;s=p.lstat();now={'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()}
 if now!=old:changes.append(n)
assert not changes,'Historical content or metadata changed: '+str(changes)
files=sorted(str(p.relative_to(ROOT)) for p in (ROOT/'evidence').rglob('*') if p.is_file() and not p.is_relative_to(OUT));assert files==base['historicalEvidenceFileList'],'Historical file list changed'
for n,x in base['approvedExistingChanges'].items():assert hashlib.sha256(subprocess.check_output(['git','show',base['head']+':'+n],cwd=ROOT)).hexdigest()==x['sha256']
code=json.loads((OUT/'code-sha256.json').read_text());assert all(sha(ROOT/n)==h for n,h in code.items()),'Current code changed'
main=json.loads((OUT/'linux-package-attempt2.json').read_text());different=[n for n,h in main['files'].items() if sha(ROOT/n)!=h];assert different==['infra/security/testing/cosign-real-suite.mjs'],'Native executed code drift'
# Only the supplemental test-mode output filename/log count was changed after
# the main 17-case run. All operational runner/core/policy files match exactly.
missing=json.loads((OUT/'actual-missing-tool-execution.json').read_text());assert missing['exit']==0 and missing['temporaryDomainRemoved'];assert all(sha(ROOT/n)==h for n,h in missing['codeHashes'].items())
export=json.loads((OUT/'export-proof.json').read_text());assert export['fakePlaintextAbsent'] and not export['privateKeyExported']
assert all(sha(OUT/'real-linux'/n)==h['sha256'] for n,h in export['manifest'].items()),'Export bytes changed'
cleanup=json.loads((OUT/'linux-cleanup.json').read_text());assert cleanup['workspaceRemoved'] and cleanup['residualProcesses']==0 and cleanup['privateKeyFiles']==0
pre=json.loads((OUT/'write-boundary-preflight.json').read_text());assert all(v=='DENIED' for v in pre['denied'].values())
offline=json.loads((OUT/'offline-attempt3.json').read_text());assert offline['tests']==offline['pass']==393 and offline['fail']==0 and not offline['contentChanges'] and not offline['metadataChanges']
diff=json.loads((OUT/'legacy-cosign-differential-attempt3.json').read_text())['records'];assert len(diff)==260 and all(x['oldDecision']==x['standardDecision'] for x in diff)
assert all(json.loads((OUT/'production-comparison.json').read_text())['checks'].values())
v=json.loads((OUT/'VERDICT.json').read_text())['verdict'];assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED' and v['FINAL_WIRED_CAPABILITY']=='14/16'
sealed=json.loads((OUT/'evidence-sha256.json').read_text());actual={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'};assert sealed==actual,'This round evidence changed'
print(json.dumps({'newRoundSeal':'VERIFIED_SCOPED','protectedFilesContentAndMetadataUnchanged':len(base['protected']),'historicalFileListUnchanged':True,'writeBoundary':'VERIFIED_OS_SANDBOX','oldCosignDifferentialSamples':260,'offlineTests':393,'sameRoundNativeMatrixCases':17,'realAbsentToolPrerequisiteCases':1,'originalEvidenceIntegrity':'FAILED','runtime':'14/16','productionSecurityManager':'NOT_ACTIVE','release':0,'rollout':0}))
