from pathlib import Path
import subprocess,json,hashlib,tarfile,io,tempfile
R=Path.cwd();O=R/'evidence/2026-11-03/runtime-final-three'
sha=lambda b:hashlib.sha256(b).hexdigest()
prior=json.loads((R/'evidence/2026-11-02/runtime-facts-owner/runtime-source-bundle-r4.json').read_text())
files=set(prior['files']);files.update(str(p.relative_to(R)) for p in (R/'infra/security/runtime-facts').glob('*.mjs'))
tracked=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')
files.update(p for p in tracked if p and (p.startswith(('src/','.mvn/')) or p in ['pom.xml','mvnw','mvnw.cmd','.springjavaformatconfig','.editorconfig']))
head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
# Isolated Git metadata contains exactly the current commit/tree objects, not
# workstation credentials/config, hooks or unrelated history. Needed by Maven's
# unchanged git-commit-id plugin. Does not mutate the user's .git directory.
with tempfile.TemporaryDirectory(prefix='runtime-build-git-') as temp:
    base=Path(temp);subprocess.run(['git','init','-q',str(base)],check=True,capture_output=True)
    tree=subprocess.check_output(['git','ls-tree','-r','-t',head],text=True)
    ids={head,subprocess.check_output(['git','rev-parse',head+'^{tree}'],text=True).strip()}
    ids.update(line.split('\t',1)[0].split()[2] for line in tree.splitlines())
    pack=subprocess.check_output(['git','pack-objects','--stdout'],input=('\n'.join(sorted(ids))+'\n').encode())
    subprocess.run(['git','-C',str(base),'index-pack','--stdin'],input=pack,check=True,capture_output=True)
    (base/'.git/HEAD').write_text(head+'\n');(base/'.git/shallow').write_text(head+'\n')
    subprocess.run(['git','-C',str(base),'read-tree','HEAD'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(base),'config','remote.origin.url','http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git'],check=True)
    payload={p:(R/p).read_bytes() for p in sorted(files)}
    metadata={str(p.relative_to(base)):p.read_bytes() for p in (base/'.git').rglob('*') if p.is_file() and ('objects' in p.parts or p.name in ['HEAD','index','config','shallow'])}
    payload.update(metadata)
    payload['runtime-validation-run.json']=(O/'run.json').read_bytes()
    payload['runtime-accepted-extra.json']=json.dumps([json.loads((R/'evidence/2026-11-03/runtime-controlled-six'/('jenkins-build-'+str(n)+'.json')).read_text()) for n in [14,15]]).encode()
    payload['runtime-accepted-zap.json']=(R/'evidence/2026-11-03/runtime-final-four/jenkins-build-20.json').read_bytes()
    payload['runtime-accepted-baseline.json']=(R/'evidence/2026-11-02/runtime-final-eight/jenkins-build-12.json').read_bytes()
    # A separate exact tracked HEAD tree keeps collector fixtures and old scan
    # outputs outside the application build. No Maven rule/exclusion is changed.
    clean={}
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','archive',head]))) as archive:
        for member in archive.getmembers():
            if member.isdir():continue
            assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
            clean[member.name]=archive.extractfile(member).read()
    assert sha(clean['infra/security/sbom-verify.mjs'])==sha((R/'infra/security/sbom-verify.mjs').read_bytes())
    clean.update(metadata);clean['.git-sha']=(head+'\n').encode()
    cleanbytes=io.BytesIO()
    with tarfile.open(fileobj=cleanbytes,mode='w:gz') as archive:
        for name,data in sorted(clean.items()):
            t=tarfile.TarInfo(name);t.size=len(data);t.mode=0o755 if name=='mvnw' else 0o600;archive.addfile(t,io.BytesIO(data))
    payload['runtime-sbom-clean-source.tar.gz']=cleanbytes.getvalue()
    payload['runtime-sbom-clean-source.json']=(json.dumps({'schema':1,'commit':head,'classification':'EXACT_TRACKED_HEAD_BUILD_CHECKOUT_NO_LOOSE_COLLECTOR_FILES','archiveSha256':sha(cleanbytes.getvalue()),'files':{p:sha(b) for p,b in sorted(clean.items())}},indent=2)+'\n').encode()
    origin_path=R/'evidence/2026-11-01/sonar-policy/analysis-bound-facts.json'
    origin=json.loads(origin_path.read_text());origin_summary=json.loads((R/'evidence/2026-11-02/runtime-facts-owner/live-jenkins-baseline.json').read_text())
    summary=next(j for j in origin_summary['jobs'] if j['job']=='petclinic-ci')['summary']
    payload['runtime-sonar-origin.json']=(json.dumps({'binding':origin['binding'],'evidencePath':str(origin_path.relative_to(R)),'evidenceSha256':sha(origin_path.read_bytes()),'originBuild':270,'source':summary['source'],'auditTargetImage':summary['auditTargetImage'],'runtimeImage':summary['runtimeImage'],'directArchivedBuildTaskBinding':'NOT_TESTED'},indent=2)+'\n').encode()
    manifest={'schema':1,'sourceIdentity':head,'identityBasis':'exact nonrelease working-tree hashes plus minimal current-commit Git objects for unchanged Maven plugin','files':{p:sha(b) for p,b in sorted(payload.items())},'generatedGitMetadataFiles':sorted(metadata)}
    blob=json.dumps(manifest,indent=2).encode()+b'\n';(O/'runtime-source-bundle.json').write_bytes(blob)
    with tarfile.open(O/'nonrelease-source.tar.gz','w:gz') as tar:
        for name,data in {**payload,'runtime-source-bundle.json':blob,'.git-sha':(head+'\n').encode()}.items():
            t=tarfile.TarInfo(name);t.size=len(data);t.mode=0o755 if name=='mvnw' else 0o600;tar.addfile(t,io.BytesIO(data))
print(json.dumps({'files':len(payload),'generatedGitMetadata':len(metadata),'source':head,'bundleSha256':sha((O/'nonrelease-source.tar.gz').read_bytes())}))
