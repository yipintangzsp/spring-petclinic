import pathlib,json,runpy,shlex,sys
sys.dont_write_bytecode=True
root=pathlib.Path.cwd();h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
groovy=p['PREFIX']+r'''
def u=api('/users/4');assert !u.is_admin&&u.state=='active';def ms=api('/users/4/memberships');assert ms.size()==1&&ms[0].source_id==12&&ms[0].access_level==30
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/users/4/personal_access_tokens').openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='POST';c.doOutput=true;c.setRequestProperty('Content-Type','application/json');c.connectTimeout=4000;c.readTimeout=8000;c.outputStream.withCloseable{it.write(JsonOutput.toJson([name:'real-source-read-only',scopes:['read_repository'],expires_at:java.time.LocalDate.now(java.time.ZoneOffset.UTC).plusDays(1).toString()]).bytes)};assert c.responseCode==201;println(c.inputStream.text)
'''
inner=r'''
import pathlib,json,subprocess,tempfile,os,gzip,importlib.util,hashlib
r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');cfg=json.loads((r/'source-config.json').read_text());env={'PATH':'/usr/bin:/bin','HOME':str(r/'outputs'),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':str(r/'askpass.py')}
with tempfile.TemporaryDirectory(prefix='read-preflight-',dir=r/'outputs')as w:
 def git(a):
  p=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*a],cwd=w,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=45);assert p.returncode==0,'READ_ONLY_GIT_FAILED';return p.stdout
 git(['init','--bare','-q',w+'/git']);g=['--git-dir='+w+'/git'];git(g+['fetch','--depth=1','--no-tags',cfg['gitRemote'],'refs/heads/'+cfg['branch']]);commit=git(g+['rev-parse','FETCH_HEAD']).decode().strip();assert commit==cfg['commitSha'];body=git(g+['cat-file','commit',commit]);assert hashlib.sha1(b'commit '+str(len(body)).encode()+b'\0'+body).hexdigest()==commit;tree=body.splitlines()[0].decode().split()[1]
 rows=git(g+['ls-tree','-rz','--full-tree',commit]);entries={}
 for item in rows.split(b'\0'):
  if not item:continue
  meta,name=item.split(b'\t',1);mode,kind,oid=meta.decode().split();assert kind=='blob'and mode in ['100644','100755'],'SPECIAL_SOURCE_ENTRY';entries[name.decode()]={'mode':mode,'oid':oid}
 archive=gzip.compress(git(g+['archive','--format=tar','--prefix=source/',commit]),mtime=0)
 spec=importlib.util.spec_from_file_location('snapshot',r/'source-snapshot.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);proof=m.materialize_verified_archive(archive,entries,pathlib.Path(w)/'source',cfg['limits'])
 print(json.dumps({'commitSha':commit,'rootTreeOid':tree,'archiveSha256':proof['archiveSha256'],'archiveBytes':len(archive),'expandedBytes':proof['expandedBytes'],'fileCount':proof['fileCount'],'snapshotPreflightVerified':True,'scannerInvocations':0,'newCommits':0,'newPushes':0}))
'''
code=r'''
import pathlib,sys,json,subprocess,urllib.parse,os,hashlib
x=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');assert not r.exists()
q=subprocess.run(['kubectl','exec','-i','-n','ns-devops','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',x['node']],input=json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':x['groovy']}),'timeout':25000}),capture_output=True,text=True,timeout=40);assert q.returncode==0;reply=json.loads(q.stdout);assert reply['status']==200;token=json.loads(reply['body'].splitlines()[0]);assert token['scopes']==['read_repository']and token['user_id']==4
r.mkdir(mode=0o755);(r/'outputs').mkdir(mode=0o700);os.chown(r/'outputs',24021,24021);f=r/'read-token';f.write_text(token['token']);os.chown(f,0,24021);f.chmod(0o440)
(r/'askpass.py').write_text("#!/usr/bin/python3\nimport pathlib,sys\nprint('oauth2' if 'username' in sys.argv[1].lower() else pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107/read-token').read_text())\n");(r/'askpass.py').chmod(0o555)
meta=json.loads(pathlib.Path('/var/lib/security-gitops-demo/identity-metadata.json').read_text());remote='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git'
cfg={'gitRemote':remote,'branch':'security-demo/gitlab-push-20261105','commitSha':'d7faa2a512ff00b88ac3a3848fa71292b3095819','limits':{'files':1500,'archiveBytes':33554432,'expandedBytes':100663296,'fileBytes':4194304}}
(r/'source-config.json').write_text(json.dumps(cfg));(r/'source-config.json').chmod(0o444);(r/'source-snapshot.py').write_text(x['snapshot']);(r/'source-snapshot.py').chmod(0o444)
q=subprocess.run(['setpriv','--reuid=24021','--regid=24021','--clear-groups','--no-new-privs','python3','-I','-c',x['inner']],capture_output=True,text=True,timeout=120)
result={'readTokenId':token['id'],'userId':4,'sourceReadScope':['read_repository'],'credentialExported':False,'sourceReadOnly':True,'gitRemote':remote,'limits':cfg['limits']}
if q.returncode:result.update({'preflightFailed':True,'error':'READ_ONLY_SOURCE_PREFLIGHT_REJECTED','diagnosticSha256':hashlib.sha256(q.stderr.encode()).hexdigest()})
else:result.update(json.loads(q.stdout));result['temporarySourceRemoved']=not any((r/'outputs').iterdir())
print(json.dumps(result))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps({'node':p['NODE'],'groovy':groovy,'inner':inner,'snapshot':(root/'infra/security/manager-v2/ci/source-snapshot.py').read_text()}),timeout=180))
with(h/'readonly-preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
