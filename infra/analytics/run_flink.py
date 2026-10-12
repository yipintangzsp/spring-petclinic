"""Window an explicitly scoped business snapshot replay on the installed Flink."""
import argparse,copy,datetime,hashlib,json,re,shlex,time
from pathlib import Path
from controlled import HeavyRun,kube,remote


def kafka(tool,args,body=None,timeout=40):
    cmd=shlex.join(['sudo','-n','kubectl','-n','ns-bigdata','exec',*(['-i'] if body else []),'deploy/kafka','--','env','KAFKA_HEAP_OPTS=-Xms32M -Xmx128M','/opt/kafka/bin/'+tool,*args])
    return remote(cmd,body,timeout)


def run(evidence):
    root=Path(__file__).parent;evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    name='petclinic-window-'+datetime.datetime.now().strftime('%H%M%S');pod=name+'-sql'
    names=['flink-jobmanager','flink-taskmanager'];old={n:kube(['-n','ns-bigdata','get','deploy',n,'-o','json']) for n in names}
    assert all(d['spec']['replicas']==0 for d in old.values()),'Do not interrupt an existing Flink task'
    (evidence/'before-private.json').write_text(json.dumps(old));(evidence/'before-private.json').chmod(0o600)
    address=kube(['-n','ns-bigdata','get','svc','flink-jobmanager','-o','json'])['spec']['clusterIP'];base='http'+'://'+address+':8081'
    statepath='/opt/petclinic-observability/state/flink/'+name;topic=name+'-input';output=name+'-output';group=name+'-consumer'
    sql=(root/'flink/clinic_windows.sql').read_text().replace('Petclinic bounded snapshot window acceptance',name+' bounded snapshot window').replace('petclinic-snapshot-20261011',topic).replace('petclinic-windows-20261011',output).replace('petclinic-flink-20261011',group)
    sql="SET 'execution.target' = 'remote';\nSET 'execution.attached' = 'false';\n"+sql
    jobs=[];savepoints=[]
    def api(path,method='GET',body=None):
        args=['curl','--noproxy','*','-fsS','--max-time','12','-X',method]
        if body is not None:args+=['-H','Content-Type: application/json','--data',json.dumps(body)]
        args+=[base+path];return json.loads(remote(shlex.join(args),timeout=20))
    with HeavyRun('flink-windows',4096,evidence) as guard:
        guard.compute_stopped=False
        try:
            for n in names:
                d=copy.deepcopy(old[n]);spec=d['spec']['template']['spec'];c=spec['containers'][0];memory=1024 if n=='flink-jobmanager' else 1536
                c['resources']={'requests':{'memory':str(memory)+'Mi','cpu':'250m'},'limits':{'memory':str(memory)+'Mi','cpu':'1000m'}}
                props='jobmanager.rpc.address: flink-jobmanager\njobmanager.rpc.port: 6123\nrest.address: flink-jobmanager\nrest.bind-address: 0.0.0.0\nparallelism.default: 1\ntaskmanager.numberOfTaskSlots: 1\njobmanager.memory.process.size: 1024m\ntaskmanager.memory.process.size: 1536m\nexecution.checkpointing.dir: file:///opt/clinic-state/checkpoints\nexecution.checkpointing.savepoint-dir: file:///opt/clinic-state/savepoints\n'
                c['env']=[e for e in c.get('env',[]) if e['name']!='FLINK_PROPERTIES']+[{'name':'FLINK_PROPERTIES','value':props}]
                spec['nodeSelector']={'kubernetes.io/hostname':'devops'}
                for volume in spec.get('volumes',[]):
                    if volume['name']=='clinic-state':assert volume.get('hostPath',{}).get('path','').startswith('/opt/petclinic-observability/state/flink/petclinic-window-')
                spec['volumes']=[v for v in spec.get('volumes',[]) if v['name']!='clinic-state']+[{'name':'clinic-state','hostPath':{'path':statepath,'type':'DirectoryOrCreate'}}]
                c['volumeMounts']=[v for v in c.get('volumeMounts',[]) if v['name']!='clinic-state']+[{'name':'clinic-state','mountPath':'/opt/clinic-state'}]
                spec['initContainers']=[i for i in spec.get('initContainers',[]) if i['name']!='prepare-clinic-state']
                for init in spec.get('initContainers',[]):init['resources']={'requests':{'memory':'128Mi','cpu':'50m'},'limits':{'memory':'128Mi','cpu':'250m'}}
                spec.setdefault('initContainers',[]).append({'name':'prepare-clinic-state','image':c['image'],'command':['sh','-c','mkdir -p /state/checkpoints /state/savepoints; chown -R "$(id -u flink):$(id -g flink)" /state; chmod 700 /state'],'securityContext':{'runAsUser':0,'runAsNonRoot':False},'resources':{'requests':{'memory':'64Mi','cpu':'25m'},'limits':{'memory':'64Mi','cpu':'100m'}},'volumeMounts':[{'name':'clinic-state','mountPath':'/state'}]})
                kube(['-n','ns-bigdata','patch','deploy',n,'--type=merge','-p',json.dumps({'spec':{'replicas':1,'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':0,'maxUnavailable':1}},'template':d['spec']['template']}})])
            for _ in range(90):
                guard.check();ready=all(kube(['-n','ns-bigdata','get','deploy',n,'-o','json'])['status'].get('readyReplicas')==1 for n in names)
                if ready:break
                time.sleep(4)
            else:raise RuntimeError('Installed Flink core did not start')
            for _ in range(30):
                guard.check()
                try:
                    overview=api('/overview')
                    if overview.get('taskmanagers',0)==1 and overview.get('slots-total',0)==1:break
                except Exception:pass
                time.sleep(2)
            else:raise RuntimeError('Flink REST/one-slot TaskManager did not become ready')
            runtime=overview.get('flink-version','');(evidence/'runtime.json').write_text(json.dumps(overview,indent=2));print('Installed runtime',runtime,flush=True)
            if runtime!='2.3.0':raise RuntimeError('Unexpected installed Flink version')
            cm=name+'-sql';kube(['create','-f','-'],{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':cm,'namespace':'ns-bigdata','labels':{'app':'petclinic-analysis'}},'data':{'job.sql':sql}})
            jm=kube(['-n','ns-bigdata','get','deploy','flink-jobmanager','-o','json']);spec=copy.deepcopy(jm['spec']['template']['spec']);spec['containers']=spec['containers'][:1];c=spec['containers'][0]
            c['name']='sql-client';c['command']=['bash','-c'];c['args']=['sleep 1800'];c['resources']={'requests':{'memory':'1024Mi','cpu':'100m'},'limits':{'memory':'1024Mi','cpu':'1000m'}}
            for k in ['readinessProbe','livenessProbe','startupProbe']:c.pop(k,None)
            spec['automountServiceAccountToken']=False;spec['restartPolicy']='Never';spec['activeDeadlineSeconds']=1800
            spec['volumes'].append({'name':'clinic-sql','configMap':{'name':cm}});c['volumeMounts'].append({'name':'clinic-sql','mountPath':'/opt/clinic','readOnly':True})
            kube(['create','-f','-'],{'apiVersion':'v1','kind':'Pod','metadata':{'name':pod,'namespace':'ns-bigdata','labels':{'app':'petclinic-analysis'}},'spec':spec})
            for _ in range(45):
                guard.check();p=kube(['-n','ns-bigdata','get','pod',pod,'-o','json'])
                if any(c.get('ready') for c in p['status'].get('containerStatuses',[])):break
                time.sleep(3)
            else:raise RuntimeError('Flink SQL client did not start')
            # New, scoped topics only. Existing log/release topics and offsets are preserved.
            for t in [topic,output]:
                result=kafka('kafka-topics.sh',['--bootstrap-server','localhost:9092','--create','--if-not-exists','--topic',t,'--partitions','1','--replication-factor','1','--config','retention.ms=604800000'])
                (evidence/(t+'.txt')).write_text(result)
            def submit(savepoint=None):
                script=sql if savepoint is None else "SET 'execution.savepoint.path' = '"+savepoint+"';\n"+sql
                kube(['-n','ns-bigdata','patch','cm',cm,'--type=merge','-p',json.dumps({'data':{'job.sql':script}})])
                # Projected volumes update asynchronously; copy exact SQL through stdin instead.
                expectedhash=hashlib.sha256(script.encode()).hexdigest()
                for _ in range(45):
                    guard.check();actual=str(kube(['-n','ns-bigdata','exec',pod,'--','sha256sum','/opt/clinic/job.sql'])).split()[0]
                    if actual==expectedhash:break
                    time.sleep(2)
                else:raise RuntimeError('Projected SQL did not match its reviewed SHA256')
                log=str(kube(['-n','ns-bigdata','exec',pod,'--','/opt/flink/bin/sql-client.sh','-Drest.address=flink-jobmanager','-Drest.port=8081','-Djobmanager.rpc.address=flink-jobmanager','-f','/opt/clinic/job.sql'],timeout=90));(evidence/('sql-submit-'+str(len(jobs))+'.log')).write_text(log)
                if re.search(r'\[ERROR\]|Exception in thread|Could not execute',log):raise RuntimeError('Flink SQL submission failed; see private SQL evidence')
                ids=re.findall(r'Job ID:\s*([a-f0-9]{32})',log)
                if not ids:ids=re.findall(r'([a-f0-9]{32})',log)
                overview=api('/jobs/overview');running=[j for j in overview['jobs'] if j['state']=='RUNNING']
                if len(running)!=1:raise RuntimeError('No unique running Flink SQL job')
                job=running[0]['jid'];jobs.append(job);return job
            job=submit()
            # The only new event source is a bounded, explicit replay, not a transactional CDC claim.
            csv=remote("sudo -n kubectl -n ns-data exec deploy/postgresql -- psql -U postgres -d petclinic -Atc \"SET statement_timeout='5s'; COPY (SELECT id,visit_date FROM visits ORDER BY id LIMIT 5001) TO STDOUT WITH CSV;\"")
            rows=[line.split(',') for line in csv.splitlines() if line!='SET'];assert 0<len(rows)<=5000
            def produce(snapshot):
                body='\n'.join(json.dumps({'snapshot_id':snapshot,'visit_id':int(row[0]),'visit_date':row[1]}) for row in rows)+'\n'
                kafka('kafka-console-producer.sh',['--bootstrap-server','localhost:9092','--topic',topic,'--producer-property','acks=all','--producer-property','enable.idempotence=true'],body,timeout=60)
            produce(name+'-first');expected=len(rows)
            def output_rows():
                command=shlex.join(['sudo','-n','kubectl','-n','ns-bigdata','exec','deploy/kafka','--','env','KAFKA_HEAP_OPTS=-Xms32M -Xmx128M','/opt/kafka/bin/kafka-console-consumer.sh','--bootstrap-server','localhost:9092','--topic',output,'--from-beginning','--timeout-ms','5000','--max-messages','5000','--consumer-property','isolation.level=read_committed','--property','print.key=true','--property','key.separator=\t'])
                text=remote(command+' 2>/dev/null || test "$?" -eq 1',timeout=30)
                values={}
                for line in text.splitlines():
                    if '\t' in line:
                        k,v=line.split('\t',1)
                        if v not in ['null','']:
                            if k in values:raise RuntimeError('Duplicate final window key in committed Kafka output')
                            values[k]=json.loads(v)
                return list(values.values())
            def verify(snapshot):
                for _ in range(20):
                    guard.check();values=output_rows();count=sum(v['visits'] for v in values if v['snapshot_id']==snapshot)
                    if count==expected:return values
                    if count>expected:raise RuntimeError('Flink replay window count duplicated input')
                    state=api('/jobs/'+jobs[-1]);
                    if state['state']!='RUNNING':raise RuntimeError('Flink job failed during replay')
                    time.sleep(3)
                raise RuntimeError('Window output did not reconcile with bounded snapshot')
            first=verify(name+'-first')
            expectedyear=sum('2026-01-01'<=r[1]<='2026-12-31' for r in rows)
            actualyear=sum(v['visits'] for v in first if v['snapshot_id']==name+'-first' and '2026-01-01'<=v['visit_date']<='2026-12-31')
            assert actualyear==expectedyear,'Flink date dimension did not reconcile'
            checks=api('/jobs/'+job+'/checkpoints');(evidence/'checkpoints-first.json').write_text(json.dumps(checks,indent=2))
            assert checks['counts']['completed']>0,'No actual completed checkpoint'
            def stop_savepoint(job):
                response=api('/jobs/'+job+'/stop','POST',{'drain':False,'targetDirectory':'file:///opt/clinic-state/savepoints','formatType':'CANONICAL'})
                trigger=response['request-id']
                for _ in range(30):
                    guard.check();result=api('/jobs/'+job+'/savepoints/'+trigger)
                    if result['status']['id']=='COMPLETED':
                        operation=result['operation']
                        if operation.get('failure-cause'):raise RuntimeError('Savepoint operation failed')
                        path=operation['location'];savepoints.append(path);return path
                    time.sleep(2)
                raise RuntimeError('Savepoint deadline exceeded')
            saved=stop_savepoint(job);restored=submit(saved);time.sleep(8)
            restorechecks=api('/jobs/'+restored+'/checkpoints');(evidence/'checkpoints-restored.json').write_text(json.dumps(restorechecks,indent=2))
            assert restorechecks.get('latest',{}).get('restored'),'Restore did not report an actual restored savepoint'
            first_after=output_rows();assert sum(v['visits'] for v in first_after if v['snapshot_id']==name+'-first')==expected
            produce(name+'-second');second=verify(name+'-second');finalsave=stop_savepoint(restored)
            offsets=kafka('kafka-consumer-groups.sh',['--bootstrap-server','localhost:9092','--describe','--group',group]);(evidence/'consumer-offsets.txt').write_text(offsets)
            result={'runtime':runtime,'sourceKind':'demo','inputKind':'bounded database snapshot replay, not CDC','inputRowsPerReplay':expected,'windowVisits2026':actualyear,'jobs':jobs,'savepoints':savepoints,'completedCheckpoints':checks['counts']['completed'],'firstOutputCount':sum(v['visits'] for v in first if v['snapshot_id']==name+'-first'),'secondOutputCount':sum(v['visits'] for v in second if v['snapshot_id']==name+'-second'),'restored':True,'stateHostPath':statepath,'inputTopic':topic,'outputTopic':output,'consumerGroup':group}
            (evidence/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
        finally:
            # Stop all owned jobs before scaling core down; preserve every state directory/topic.
            try:
                for j in api('/jobs/overview').get('jobs',[]):
                    if j['state']=='RUNNING' and (j['jid'] in jobs or j.get('name')==name+' bounded snapshot window'):
                        try:api('/jobs/'+j['jid']+'?mode=cancel','PATCH')
                        except json.JSONDecodeError:pass
            except Exception:pass
            for n in names:
                try:(evidence/(n+'.log')).write_text(str(kube(['-n','ns-bigdata','logs','deploy/'+n,'--tail=160'])))
                except Exception:pass
                kube(['-n','ns-bigdata','scale','deploy',n,'--replicas=0'])
            kube(['-n','ns-bigdata','delete','pod',pod,'--ignore-not-found','--wait=false'])
            for _ in range(50):
                p=kube(['-n','ns-bigdata','get','pods','-o','json'])['items']
                active=[x for x in p if (x['metadata']['name']==pod or any(x['metadata']['name'].startswith(n+'-') for n in names)) and x['status']['phase'] not in ['Succeeded','Failed']]
                if not active:break
                time.sleep(3)
            else:raise RuntimeError('Flink compute remains; retain resource Lease')
            guard.compute_stopped=True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();run(a.evidence)
