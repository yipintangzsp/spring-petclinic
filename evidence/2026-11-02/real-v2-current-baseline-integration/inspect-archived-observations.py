"""Read-only live Jenkins inventory through the already authorized relay.

Never prints credentials, job XML or console text. Uses strict trusted host keys.
No build trigger, config update, scanner, approval, signing, Git push or deploy.
"""
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, '/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE

base = pathlib.Path(__file__).parent
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=6', '-o', 'ConnectionAttempts=1',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'HostName=192.168.64.11',
       '-o', 'HostKeyAlias=192.168.1.58', 'zhang@192.168.1.58']
script = "\nimport groovy.json.JsonOutput\nimport groovy.json.JsonSlurperClassic\nimport java.security.MessageDigest\ndef j=Jenkins.instance.getItemByFullName('petclinic-ci'),b=j.lastBuild\ndef req=[sops:[file:'secrets-gate.json',keys:['prerequisites','targets','rbac','reportWriteSucceeded']],kyverno:[file:'admission-gate.json',keys:['configuration','observations']],kubescape:[file:'kubescape-gate.json',keys:['lock','observations']],cosign:[file:'signing-admission.json',keys:['stage','configuration','runtime','commands','io']],defectdojo:[file:'defectdojo-import.json',keys:['files','target','api','credentials']],falco:[file:'runtime-health.json',keys:['configuration','observations']]]\ndef rows=req.collect{k,v->\n def a=b.artifacts.find{it.relativePath=='.devsecops/'+v.file}\n def f=a?new File(b.artifactsDir,a.relativePath):null\n def text=f?.isFile()?f.getText('UTF-8'):null\n def obj=text==null?null:new JsonSlurperClassic().parseText(text)\n [source:k,path:a?.relativePath,exists:obj!=null,status:obj?.status,sha256:text==null?null:MessageDigest.getInstance('SHA-256').digest(text.getBytes('UTF-8')).encodeHex().toString(),topLevelFields:obj?.keySet()?.sort(),requiredObservationFields:v.keys,requiredFieldsPresent:v.keys.collectEntries{key->[(key):obj?.containsKey(key)==true]}]\n}\nprintln(JsonOutput.toJson([classification:'HISTORICAL_NATIVE_REPORT_SCHEMA_ONLY_NOT_NEW_RUNTIME_FACTS',job:j.fullName,build:b.number,result:b.result.toString(),rows:rows,credentialsOrRawReportValuesExported:false,productionModified:false]))\n"

payload = {'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000}
command = 'sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e ' + shlex.quote(NODE)
result = subprocess.run(ssh + [command],input=json.dumps(payload),capture_output=True,text=True,timeout=60)
if result.returncode: raise SystemExit('Trusted SSH inspection failed, exit '+str(result.returncode))
response=json.loads(result.stdout)
if response['status']!=200: raise SystemExit('Read-only Jenkins response '+str(response['status']))
data=json.loads(response['body'].split('\n',1)[0])
(base/'archived-native-observation-contract.json').write_text(json.dumps(data,indent=2)+'\n')
print(json.dumps({'build':data['build'],'nativeReportsReviewed':len(data['rows']),'newRuntimeFacts':False,'productionModified':False}))
