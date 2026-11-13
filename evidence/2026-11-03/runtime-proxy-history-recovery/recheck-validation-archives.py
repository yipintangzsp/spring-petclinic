from pathlib import Path
import json,subprocess,sys,shlex,urllib.parse,hashlib
O=Path(__file__).resolve().parent;P=O.parent/'runtime-independent-boundaries';sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
script='''import groovy.json.JsonOutput
import java.security.MessageDigest
def j=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102')
def builds=[32,33].collect{n->def b=j.getBuildByNumber(n);assert b!=null&&!b.building;def hashes=[:];b.artifacts.findAll{it.relativePath.startsWith('.devsecops/runtime-controlled/')&&it.relativePath.endsWith('.json')}.each{a->def f=new File(b.artifactsDir,a.relativePath);assert f.isFile();hashes[a.relativePath]=MessageDigest.getInstance('SHA-256').digest(f.bytes).encodeHex().toString()};[build:n,result:b.result.toString(),artifactHashes:hashes]}
println(JsonOutput.toJson([job:j.fullName,latestBuild:j.lastBuild.number,latestBuilding:j.lastBuild.building,definitionSha256:MessageDigest.getInstance('SHA-256').digest(j.definition.script.bytes).encodeHex().toString(),builds:builds,readOnly:true]))'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=60);assert p.returncode==0,'TRUSTED_SSH_FAILED';r=json.loads(p.stdout);assert r['status']==200;x=json.loads(r['body'].split('\n',1)[0]);assert not x['latestBuilding'] and x['latestBuild']==33
for b in x['builds']:
 old=json.load(open(P/('jenkins-build-'+str(b['build'])+'.json')));assert b['result']=='SUCCESS' and old['result']==b['result'];assert old['artifactHashes']==b['artifactHashes'];b['matchesSealedPriorEvidence']=True
assert x['definitionSha256']==hashlib.sha256((P/'Jenkinsfile.runtime-facts.before').read_bytes()).hexdigest();(O/'validation-archives-recheck.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'builds':[(b['build'],b['result'],len(b['artifactHashes'])) for b in x['builds']],'archiveHashesUnchanged':True,'jobUnchanged':True,'readOnly':True}))
