from pathlib import Path
import importlib.util,json,subprocess,shlex,time
R=Path.cwd();O=R/'evidence/2026-11-02/runtime-final-eight'
spec=importlib.util.spec_from_file_location('fixture',O/'sops_fixture.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
build=12
remote=f'/var/jenkins_home/workspace/security-runtime-facts-20261102/.devsecops/runtime-facts/build-{build}/isolated-sops-request.json'
request=None
for _ in range(180):
 p=subprocess.run(f.SSH+['sudo -n kubectl exec -n ns-devops deploy/jenkins -c jenkins -- cat '+shlex.quote(remote)],capture_output=True,timeout=20)
 if p.returncode==0:
  request=json.loads(p.stdout);break
 time.sleep(3)
if not request:raise SystemExit('NO_ISOLATED_HANDSHAKE')
assert request['binding']['build']==build and request['binding']['job']=='security-runtime-facts-20261102'
packet=f.execute(request['binding'],'POSITIVE');assert packet['oldExit']==0
packet['nonce']=request['nonce'];raw=packet['envelope']['facts']['raw']
# Raw stdout/decrypted synthetic data remain in memory. Record only safe field
# presence and UID preservation comparisons, never values or decrypted JSON.
shapes={'prerequisites':list(raw.get('prerequisites',{})),'targets':len(raw.get('targets',[])),'targetFields':[list(t) for t in raw.get('targets',[])],'rbacPresent':bool(raw.get('rbac')),'verifierRbacPresent':bool(raw.get('verifierRbac')),'readOnly':raw.get('readOnly'),'expectedTargetCount':raw.get('expectedTargetCount')}
writer="const fs=require('fs'),p=process.argv[1];if(!/^\\/tmp\\/runtime-isolated-facts-[^/]+\\/sops\\.fifo$/.test(p)||!fs.lstatSync(p).isFIFO())throw Error('not private FIFO');const b=fs.readFileSync(0);if(b.length>4194304)throw Error('oversize');fs.writeFileSync(p,b);console.log('ISOLATED_PACKET_DELIVERED')"
command='sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(writer)+' '+shlex.quote(request['fifo'])
p=subprocess.run(f.SSH+[command],input=(json.dumps(packet)+'\n').encode(),capture_output=True,timeout=30)
assert p.returncode==0,p.stderr.decode()[-200:]
receipt={'build':build,'binding':request['binding'],'executionScope':packet['executionScope'],'scenario':packet['scenario'],'oldExit':packet['oldExit'],'rawFactDigest':packet['envelope']['rawFactDigest'],'envelopeDigest':packet['envelope']['envelopeDigest'],'guard':packet['guard'],'factShape':shapes,'transport':'STDIN_TO_PRIVATE_FIFO','rawPayloadPersisted':False,'secretMaterialLogged':False,'productionSecretAccess':0,'productionAgeKeyAccess':0,'deliveryExit':p.returncode}
(O/'isolated-delivery-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'ISOLATED_PACKET_DELIVERED','build':build,'oldExit':packet['oldExit'],'rawFactDigest':receipt['rawFactDigest']}))
