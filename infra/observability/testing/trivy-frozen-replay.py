"""Non-release trusted test runner: immutable source input, fresh output, private cwd.

It never runs untrusted code and is not a kernel sandbox. A Node API preloader catches
accidental writes outside the copy; cwd/TMPDIR bound trusted child oracle outputs.
"""
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, tempfile

ROOT=pathlib.Path(__file__).resolve().parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require_fresh_output(parent,name):
    parent=pathlib.Path(parent).resolve()
    if not (parent/'.guard-boundary-run.json').is_file():raise RuntimeError('NEW_EVIDENCE_RUN_MARKER_REQUIRED')
    if any((parent/n).exists() for n in ['evidence-sha256.json','artifact-sha256.json']):
        raise RuntimeError('SEALED_EVIDENCE_OUTPUT_DENIED')
    if name not in ['original-v1','helm-versioned','legacy-guard','regression','runtime','policy-core','helm-shadow','source-lock','contract']:
        raise RuntimeError('UNKNOWN_TEST_SUITE')
    out=parent/name;out.mkdir(exist_ok=False);return out
def run(parent,mode):
    out=require_fresh_output(parent,mode)
    protected=json.loads((pathlib.Path(parent)/'baseline.json').read_text())['protectedFilesAtStart']
    for p,h in protected.items():
        if sha(ROOT/p)!=h:raise RuntimeError('HISTORICAL_INPUT_CHANGED')
    lock=json.loads((ROOT/'infra/security/policy/versions/trivy-parent-baseline-v1.json').read_text())
    with tempfile.TemporaryDirectory(prefix='trivy-frozen-guard-replay-') as d:
        root=pathlib.Path(d).resolve();os.chmod(root,0o700)
        for prefix in ['infra/security','infra/observability','vars','resources','infra/helm','charts/petclinic']:
            shutil.copytree(ROOT/prefix,root/prefix,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        for p in set(lock['sourceHashes'])|{'Jenkinsfile.helm-shadow','Jenkinsfile.candidate-build','infra/argocd/petclinic-helm-candidate.yaml'}:
            if (ROOT/p).is_file():
                (root/p).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/p,root/p)
        # Runtime tests validate other frozen parents too. Copy their pinned source
        # dependencies, never replace their manifests or source bytes to make them pass.
        for manifest in (ROOT/'infra/security/policy/versions').glob('*.json'):
            for key,entries in json.loads(manifest.read_text()).items():
                if not isinstance(entries,dict) or not key.lower().endswith('hashes'):continue
                for name,digest in entries.items():
                    p=pathlib.Path(name)
                    if p.is_absolute() or '..' in p.parts:raise RuntimeError('UNSAFE_SOURCE_DEPENDENCY')
                    if not isinstance(digest,str) or not (ROOT/p).is_file():continue
                    (root/p).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/p,root/p)
        p=pathlib.Path('evidence/2026-11-01/policy-engine/gate-decision-before.json')
        (root/p).parent.mkdir(parents=True);shutil.copyfile(ROOT/p,root/p)
        (root/'evidence/2026-11-01/trivy-parent/fixtures').mkdir(parents=True)
        (root/'tmp').mkdir(mode=0o700);(root/'.frozen-replay.json').write_text('{"schema":1}')
        if mode=='helm-shadow':
            lockHelm=json.loads((ROOT/'infra/helm/tools-lock.json').read_text())
            key=('darwin' if platform.system()=='Darwin' else 'linux')+'-'+('arm64' if platform.machine() in ['arm64','aarch64'] else 'amd64')
            relative=pathlib.Path('.tools/helm')/lockHelm['helmVersion']/key/'helm'
            source=ROOT/relative
            if not source.is_file() or sha(source)!=lockHelm['platforms'][key]['binarySha256']:
                raise RuntimeError('EXISTING_PINNED_HELM_REQUIRED_NO_NETWORK_DOWNLOAD')
            (root/relative).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,root/relative)
        if mode=='original-v1':
            shutil.copyfile(ROOT/'infra/security/policy/versions/trivy-parent.frozen-v1.mjs',root/'infra/security/policy/trivy-parent.mjs')
            (root/'Jenkinsfile.security-audit').write_bytes(subprocess.check_output(['git','show','741ea28:Jenkinsfile.security-audit'],cwd=ROOT))
            assert all(sha(root/p)==h for p,h in lock['sourceHashes'].items())
        if mode=='legacy-guard':
            for name in ['scanner-validation-guard.mjs','testing/scanner-validation-guard.test.mjs','testing/scanner-validation-review.test.mjs']:
                shutil.copyfile(pathlib.Path(parent)/(pathlib.Path(name).name+'.before'),root/'infra/observability'/name)
        suites={
         'original-v1':['infra/security/policy/trivy-db.test.mjs','infra/security/policy/trivy-parent.test.mjs','infra/security/policy/trivy-parent-workflow.test.mjs'],
         'helm-versioned':['infra/security/policy/trivy-db.test.mjs','infra/security/policy/trivy-parent.test.mjs','infra/security/policy/trivy-parent-workflow.test.mjs'],
         'legacy-guard':['infra/observability/testing/scanner-validation-guard.test.mjs','infra/observability/testing/scanner-validation-review.test.mjs'],
         'regression':[str(p.relative_to(ROOT)) for prefix in ['infra/observability','infra/security'] for p in sorted((ROOT/prefix).glob('*.test.mjs'))],
         'policy-core':['infra/security/policy/engine.test.mjs'],
         'source-lock':['infra/security/policy/trivy-source-lock.test.mjs'],
         'helm-shadow':['infra/helm/chart.test.mjs','infra/helm/pipeline-contract.test.mjs'],
        }
        previous=ROOT/'evidence/2026-11-04/trivy-compatibility-capacity-review'
        if mode=='runtime':suites[mode]=json.loads((previous/'runtime-tests-execution.json').read_text())['command'][3:]
        if mode=='contract':
            shutil.copyfile(previous/'policy-contract-check.mjs',root/'policy-contract-check.mjs')
            # The assertions use cwd for source reads but their output resolves relative to the script.
            script=(root/'policy-contract-check.mjs').read_text()
            script=script.replace("../../../infra/", "./infra/")
            (root/'policy-contract-check.mjs').write_text(script)
        preload='infra/observability/testing/frozen-evidence-writes.mjs'
        # Old reproduction tests deliberately create their own OS-temp fixtures; private TMPDIR
        # and copied cwd keep them disposable. Preloader remains active for all Node test suites.
        command=['node','--import','./'+preload]+(['policy-contract-check.mjs'] if mode=='contract' else ['--test','--test-concurrency=1',*suites[mode]])
        environment={**os.environ,'TRIVY_FROZEN_REPLAY_ROOT':str(root),'TMPDIR':str(root/'tmp'),'TMP':str(root/'tmp'),'TEMP':str(root/'tmp')}
        with (out/'tests.log').open('w') as log:
            result=subprocess.run(command,cwd=root,env=environment,stdout=log,stderr=subprocess.STDOUT)
        if mode=='contract' and (root/'policy-contract.json').exists():shutil.copyfile(root/'policy-contract.json',out/'policy-contract.json')
        if mode in ['original-v1','helm-versioned']:
            shutil.copytree(root/'evidence/2026-11-01/trivy-parent',out/'generated-evidence')
        (out/'execution.json').write_text(json.dumps({'mode':mode,'command':command,'platform':platform.platform(),'arch':platform.machine(),'exit':result.returncode,
            'sourceHashes':{p:sha(root/p) for p in lock['sourceHashes']},'nodeAPIWriteProtection':True,'kernelSandboxClaimed':False,
            'realScannerExecutions':0,'privateTreeRemoved':True},indent=2)+'\n')
    for p,h in protected.items():
        if sha(ROOT/p)!=h:raise RuntimeError('HISTORICAL_EVIDENCE_CHANGED')
    print(json.dumps({'mode':mode,'exit':result.returncode,'protectedFiles':len(protected)}))
    return result.returncode
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode');parser.add_argument('--output',required=True)
    a=parser.parse_args();raise SystemExit(run(a.output,a.mode))
