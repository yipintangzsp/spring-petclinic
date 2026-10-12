"""A single business snapshot on the installed Spark Operator, followed by cleanup."""
import argparse,datetime,hashlib,json,time
from pathlib import Path
from controlled import HeavyRun,kube,remote

OP=['spark-operator-controller','spark-operator-webhook']


def run(image,evidence):
    root=Path(__file__).parent;evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    name='petclinic-snapshot-'+datetime.datetime.now().strftime('%H%M%S');namespace='default'
    before={n:kube(['-n','ns-bigdata','get','deploy',n,'-o','json']) for n in OP}
    assert all(d['spec']['replicas']==0 for d in before.values()),'Preserve any operator already active'
    with HeavyRun('spark-snapshot',4096,evidence) as guard:
        guard.compute_stopped=False
        try:
            text=remote("sudo -n kubectl exec -n ns-data deploy/postgresql -- psql -U postgres -d petclinic -Atc \"SET statement_timeout='5s'; COPY (SELECT id,visit_date FROM public.visits ORDER BY id LIMIT 5001) TO STDOUT WITH CSV HEADER;\"")
            lines=text.splitlines();lines=[line for line in lines if line!='SET'];assert lines[0]=='id,visit_date';assert 1<len(lines)<=5001
            csv='visit_id,visit_date\n'+'\n'.join(lines[1:])+'\n'
            expected=sum('2026-01-01'<=line.split(',')[1]<='2026-12-31' for line in lines[1:])
            proof={'inputRows':len(lines)-1,'windowVisits':expected,'snapshotSha256':hashlib.sha256(csv.encode()).hexdigest(),'sourceKind':'demo'}
            (evidence/'snapshot-proof.json').write_text(json.dumps(proof,indent=2))
            kube(['create','-f','-'],{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':namespace,'labels':{'app':'petclinic-analysis'}},'data':{'visits.csv':csv,'clinic_snapshot.py':(root/'spark/clinic_snapshot.py').read_text()}})
            for n in OP:
                d=before[n];container=d['spec']['template']['spec']['containers'][0]
                memory='1024Mi' if n.endswith('controller') else '256Mi'
                kube(['-n','ns-bigdata','patch','deploy',n,'--type=strategic','-p',json.dumps({'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':container['name'],'image':'127.0.0.1:30050/platform-upgrade/kubeflow-spark-operator-controller@sha256:68f4d74790b9a3a06f6b1ac5a5414c4b0b25c68b20ea68e8f8d87132e3a398f5','resources':{'requests':{'memory':memory,'cpu':'100m'},'limits':{'memory':memory,'cpu':'1000m'}}}]}}}})])
            for _ in range(60):
                guard.check();ready=all(kube(['-n','ns-bigdata','get','deploy',n,'-o','json'])['status'].get('readyReplicas')==1 for n in OP)
                if ready:break
                time.sleep(5)
            else:raise RuntimeError('Installed Spark operator did not become ready')
            role={'cores':1,'coreLimit':'1000m','memory':'512m','memoryOverhead':'512m',
                  'labels':{'app':'petclinic-analysis','acceptance':name},
                  'volumeMounts':[{'name':'snapshot','mountPath':'/opt/clinic','readOnly':True}],
                  'securityContext':{'runAsUser':185,'runAsGroup':185,'runAsNonRoot':True,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'RuntimeDefault'}}}
            driver={**role,'serviceAccount':'spark-operator-spark'};executor={**role,'instances':1}
            app={'apiVersion':'sparkoperator.k8s.io/v1beta2','kind':'SparkApplication',
                 'metadata':{'name':name,'namespace':namespace,'labels':{'app':'petclinic-analysis'}},
                 'spec':{'type':'Python','pythonVersion':'3','mode':'cluster','image':image,'imagePullPolicy':'IfNotPresent',
                         'sparkVersion':'4.0.1','mainApplicationFile':'local:///opt/clinic/clinic_snapshot.py',
                         'restartPolicy':{'type':'Never'},'nodeSelector':{'kubernetes.io/hostname':'devops'},
                         'sparkConf':{'spark.sql.shuffle.partitions':'1','spark.default.parallelism':'1','spark.ui.enabled':'false',
                                      'spark.driver.maxResultSize':'64m','spark.kubernetes.driver.request.cores':'1','spark.kubernetes.executor.request.cores':'1'},
                         'volumes':[{'name':'snapshot','configMap':{'name':name}}],'driver':driver,'executor':executor}}
            (evidence/'application.json').write_text(json.dumps(app,indent=2));kube(['create','-f','-'],app)
            for _ in range(90):
                guard.check();state=kube(['-n',namespace,'get','sparkapplication',name,'-o','json']);(evidence/'application-status.json').write_text(json.dumps(state,indent=2))
                status=state.get('status',{}).get('applicationState',{}).get('state')
                if status in ['COMPLETED','FAILED','SUBMISSION_FAILED']:break
                time.sleep(5)
            else:raise RuntimeError('Spark exceeded the bounded acceptance deadline')
            pod=state.get('status',{}).get('driverInfo',{}).get('podName')
            if not pod:raise RuntimeError('Spark did not create a driver')
            logs=str(kube(['-n',namespace,'logs',pod,'--tail=250']));(evidence/'driver.log').write_text(logs)
            if status!='COMPLETED':raise RuntimeError('Spark application failed: '+str(state.get('status',{}).get('applicationState')))
            matches=[line.split('CLINIC_RESULT:',1)[1] for line in logs.splitlines() if 'CLINIC_RESULT:' in line];assert len(matches)==1
            result=json.loads(matches[0]);assert result['inputRows']==proof['inputRows'];assert result['windowVisits']==proof['windowVisits'];assert result['jobIds']
            (evidence/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:result[k] for k in ['applicationId','jobIds','inputRows','windowVisits','sparkVersion','durationSeconds']}),flush=True)
        finally:
            # Preserve the snapshot ConfigMap and private output; release only task compute.
            kube(['-n',namespace,'delete','sparkapplication',name,'--ignore-not-found','--wait=false'])
            for n in OP:
                try:(evidence/(n+'.log')).write_text(str(kube(['-n','ns-bigdata','logs','deploy/'+n,'--tail=100'])))
                except Exception:pass
                kube(['-n','ns-bigdata','scale','deploy',n,'--replicas=0'])
            for _ in range(50):
                pods=kube(['get','pods','-A','-o','json'])['items']
                active=[p for p in pods if (p['metadata'].get('labels',{}).get('acceptance')==name or any(p['metadata']['name'].startswith(n+'-') for n in OP)) and p['status']['phase'] not in ['Succeeded','Failed']]
                if not active:break
                time.sleep(3)
            else:raise RuntimeError('Spark compute remains active; retain heavy Lease')
            guard.compute_stopped=True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--evidence',required=True);a=p.parse_args();run(a.image,a.evidence)
