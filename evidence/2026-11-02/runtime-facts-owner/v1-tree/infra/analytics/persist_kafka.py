"""Preserve the existing single-broker log directory on the existing VM disk."""
import argparse,json,shlex,time
from pathlib import Path
from controlled import HeavyRun,kube,remote

BACKUP_CODE=r'''import json,subprocess,pathlib,hashlib,tarfile,os,datetime
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
base=pathlib.Path('/opt/petclinic-observability/backups/platform-20261011/kafka-preserved-'+stamp);base.mkdir(mode=0o700,exist_ok=False)
archive=base/'original-kafka-logs.tar.gz'
args=['kubectl','-n','ns-bigdata','exec','deploy/kafka','--','sh','-c',"set -e; trap 'kill -CONT 1' EXIT HUP INT TERM; kill -STOP 1; sync; tar -cz -C /tmp kafka-logs"]
try:
 with archive.open('wb') as file:
  p=subprocess.run(args,stdout=file,stderr=subprocess.PIPE,timeout=45)
  if p.returncode:raise RuntimeError('Kafka log preservation failed')
finally:
 subprocess.run(['kubectl','-n','ns-bigdata','exec','deploy/kafka','--','kill','-CONT','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
archive.chmod(0o600)
with tarfile.open(archive,'r:gz') as tar:
 members=tar.getmembers()
 assert members and all(m.name=='kafka-logs' or m.name.startswith('kafka-logs/') for m in members)
 assert all(not m.issym() and not m.islnk() and '..' not in pathlib.PurePosixPath(m.name).parts for m in members)
 tar.extractall(base/'restored',filter='data')
root=base/'restored/kafka-logs'
manifest=[]
for path in sorted(root.rglob('*')):
 os.chown(path,1000,1000)
 if path.is_file():
  with path.open('rb') as f:
   digest=hashlib.file_digest(f,'sha256').hexdigest()
  manifest.append({'path':str(path.relative_to(root)),'size':path.stat().st_size,'sha256':digest})
os.chown(root,1000,1000);os.chmod(root,0o750)
# The runtime can traverse to its own directory, while backups remain root-only.
state=pathlib.Path('/opt/petclinic-observability/state/kafka-'+stamp);state.mkdir(mode=0o750,parents=True,exist_ok=False)
os.chown(state,1000,1000)
subprocess.run(['cp','-a',str(root),str(state/'data')],check=True)
proof={'archiveBytes':archive.stat().st_size,'archiveSha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'files':manifest,'statePath':str(state/'data'),'sourceDir':'/tmp/kafka-logs'}
(base/'manifest.json').write_text(json.dumps(proof,indent=2));os.chmod(base/'manifest.json',0o600)
print(json.dumps({'archiveBytes':proof['archiveBytes'],'archiveSha256':proof['archiveSha256'],'fileCount':len(manifest),'statePath':proof['statePath']}))'''


def cli(tool,args):
    return remote(shlex.join(['sudo','-n','kubectl','-n','ns-bigdata','exec','deploy/kafka','--','env','KAFKA_HEAP_OPTS=-Xms32M -Xmx128M','/opt/kafka/bin/'+tool,*args]),timeout=25)


def run(evidence):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    old=kube(['-n','ns-bigdata','get','deploy','kafka','-o','json']);spec=old['spec']['template']['spec']
    assert not any(v.get('name')=='preserved-kafka' for v in spec.get('volumes',[])),'Already preserved; verify instead of repeating migration'
    (evidence/'before-private.json').write_text(json.dumps(old));(evidence/'before-private.json').chmod(0o600)
    with HeavyRun('kafka-preservation',1536,evidence) as guard:
        offsets=cli('kafka-get-offsets.sh',['--bootstrap-server','localhost:9092','--time','-1']);(evidence/'offsets-before.txt').write_text(offsets)
        topics=cli('kafka-topics.sh',['--bootstrap-server','localhost:9092','--describe']);(evidence/'topics-before.txt').write_text(topics)
        proof=json.loads(remote('sudo -n python3 -c '+shlex.quote(BACKUP_CODE),timeout=70));(evidence/'preservation-proof.json').write_text(json.dumps(proof,indent=2));guard.check()
        c=spec['containers'][0];env=[e for e in c.get('env',[]) if e['name']!='KAFKA_LOG_DIRS']+[{'name':'KAFKA_LOG_DIRS','value':'/tmp/kafka-logs'}]
        patch={'spec':{'strategy':{'type':'Recreate','rollingUpdate':None},'template':{'spec':{'nodeSelector':{'kubernetes.io/hostname':'devops'},'volumes':[{'name':'preserved-kafka','hostPath':{'path':proof['statePath'],'type':'Directory'}}],'containers':[{'name':c['name'],'env':env,'resources':{'requests':{'memory':'1Gi','cpu':'250m'},'limits':{'memory':'1Gi','cpu':'1000m'}},'volumeMounts':[{'name':'preserved-kafka','mountPath':'/tmp/kafka-logs'}]}]}}}}
        kube(['-n','ns-bigdata','patch','deploy','kafka','--type=strategic','-p',json.dumps(patch)])
        for _ in range(60):
            guard.check();d=kube(['-n','ns-bigdata','get','deploy','kafka','-o','json'])
            if d['status'].get('observedGeneration',0)>=d['metadata']['generation'] and d['status'].get('availableReplicas')==1:break
            time.sleep(3)
        else:raise RuntimeError('Kafka preserved-data pod did not start; retain all original archives and runtime copy')
        time.sleep(12)
        after=cli('kafka-get-offsets.sh',['--bootstrap-server','localhost:9092','--time','-1']);(evidence/'offsets-after.txt').write_text(after)
        beforemap={l.rsplit(':',1)[0]:int(l.rsplit(':',1)[1]) for l in offsets.splitlines() if ':' in l};aftermap={l.rsplit(':',1)[0]:int(l.rsplit(':',1)[1]) for l in after.splitlines() if ':' in l}
        assert all(aftermap.get(k,-1)>=v for k,v in beforemap.items()),'Original topic offsets did not survive'
        newtopics=cli('kafka-topics.sh',['--bootstrap-server','localhost:9092','--describe']);(evidence/'topics-after.txt').write_text(newtopics)
        result={'originalOffsets':beforemap,'retainedOffsets':aftermap,'backup':proof,'engineImage':c['image'],'node':'devops','storage':'existing VM hostPath; original archive and restored backup retained'}
        (evidence/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();run(a.evidence)
