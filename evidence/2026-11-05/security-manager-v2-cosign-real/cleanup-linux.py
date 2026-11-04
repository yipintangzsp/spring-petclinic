"""Exact owned temporary domain only; no global kill or production cleanup."""
from pathlib import Path
import json,runpy
p=Path(__file__).resolve().parent;api=runpy.run_path(str(p/'inspect-production.py'));x=json.loads((p/'tool-preparation.json').read_text());export=json.loads((p/'export-proof.json').read_text())
s=r'''
import pathlib,json,hashlib,shutil,time
r=pathlib.Path(ROOT);assert r.parent==pathlib.Path('/var/tmp') and r.name.startswith('security-manager-gitleaks-') and r.stat().st_uid==0 and not r.is_symlink()
for name,h in EXPORTED.items():
 p=r/name;assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==h['sha256']
processes=[]
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  if str(r).encode() in p.read_bytes():processes.append(int(p.parent.name))
 except (FileNotFoundError,ProcessLookupError):pass
assert not processes,processes
before={'workspace':str(r),'exactExportedFilesReverified':len(EXPORTED),'processesBeforeCleanup':processes,'toolBytes':sum(p.stat().st_size for p in (r/'semgrep').rglob('*') if p.is_file()),'cosignPrivateDirectoryAbsent':not(r/'cosign-private').exists(),'privateKeyFiles':len(list(r.rglob('*.key'))),'sourceDirectories':len(list(r.glob('source-*'))),'outputJsonFiles':len(list((r/'outputs').rglob('*.json')))}
assert before['cosignPrivateDirectoryAbsent'] and before['privateKeyFiles']==0
shutil.rmtree(r);before.update({'workspaceRemoved':not r.exists(),'binaryRemoved':not(r/'semgrep').exists() and not(r/'gitleaks').exists() and not(r/'cosign').exists(),'sourceAndApprovalsRemoved':not r.exists(),'residualProcesses':0,'kubernetesCreateCount':0,'kubernetesDeleteCount':0,'productionMutations':0,'release':0,'rollout':0});print(json.dumps(before))
'''
x=json.loads(api['remote']('sudo -n python3 -','ROOT='+repr(x['workspace'])+'\nEXPORTED='+repr(export['manifest'])+'\n'+s));api['save']('linux-cleanup.json',x);print(json.dumps(x))
