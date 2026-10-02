#!/usr/bin/env python3
"""Publish deployment health and aggregate OSINT counts; never copy secrets or target data."""
import json, subprocess, time, sqlite3, urllib.request
from pathlib import Path
KUBE=['/usr/local/bin/kubectl']
if not Path(KUBE[0]).exists(): KUBE=['/usr/local/bin/k3s','kubectl']
def kube(*args): return json.loads(subprocess.check_output(KUBE+list(args)+['-o','json'],timeout=30))
workloads=kube('get','deployment,statefulset,daemonset','-A')['items'];items=[]
links={'jenkins':'jenkins.devops.local','gitlab':'gitlab.devops.local','harbor-portal':'core.harbor.domain','kibana':'kibana.devops.local','kube-stack-grafana':'grafana.devops.local','jaeger':'jaeger.devops.local','sonarqube-sonarqube':'sonar.devops.local','airflow-api-server':'airflow.devops.local','minio':'minio.devops.local','superset':'superset.devops.local','trino-coordinator':'trino.devops.local','portainer':'portainer.devops.local','kafka-ui':'kafka.devops.local','flink-jobmanager':'flink.devops.local','zabbix-web':'zabbix.devops.local','petclinic':'petclinic.devops.local'}
wired={'kafka':'已发布版本事件流','sonarqube-sonarqube':'CI 代码分析与质量门禁','gitlab':'Git 源码镜像','gitlab-runner':'源码镜像审计任务','harbor-core':'镜像归档与漏洞扫描请求','harbor-registry':'双架构镜像审计副本','harbor-trivy':'漏洞扫描后端','petclinic':'业务应用','jenkins':'CI 构建与发布','local-registry':'双架构镜像仓库','argocd-application-controller':'GitOps 发布','argocd-repo-server':'Git 源码拉取','postgresql':'业务数据源','filebeat':'Elasticsearch 日志采集','alloy':'Loki 日志采集','loki':'Grafana 日志存储','elasticsearch':'Kibana 日志存储','kibana':'结构化业务与请求日志','kube-stack-grafana':'运行与业务仪表盘','prometheus-kube-stack-kube-prometheus-prometheus':'应用与业务指标采集','otel-collector':'OTLP 请求链路转发','jaeger':'请求链路存储与查询'}
for w in sorted(workloads,key=lambda w:(w['metadata']['namespace'],w['metadata']['name'])):
 n=w['metadata']['name'];ns=w['metadata']['namespace'];st=w.get('status',{});ds=w['kind']=='DaemonSet'
 desired=st.get('desiredNumberScheduled',0) if ds else w['spec'].get('replicas',1)
 ready=st.get('numberReady',0) if ds else st.get('readyReplicas',0)
 items.append({'id':ns+'/'+n,'name':n,'namespace':ns,'kind':w['kind'],'desired':desired,'ready':ready,'endpoint':links.get(n,''),'integration':wired.get(n,'部署状态已同步，业务链路待接入')})
root=Path('/opt/osint-platform');smoke=root/'evidence/smoke.json'
if smoke.exists():
 try:
  with urllib.request.urlopen('http://192.168.1.58:18090/healthz',timeout=3) as response: platform_up=response.status==200
 except OSError: platform_up=False
 checks=json.loads(smoke.read_text());names={'blackbird':'Blackbird','maigret':'Maigret','spiderfoot':'SpiderFoot','theHarvester':'theHarvester','shodan-python':'Shodan Python'}
 for k,v in checks.items():items.append({'id':'osint/'+k,'name':names[k],'namespace':'独立工具平台','kind':'Python runtime','desired':1,'ready':int(v.get('exitcode')==0 and platform_up and (root/'runtimes'/k/'bin/python').exists()),'endpoint':'192.168.1.58:18090','integration':'CLI 安装已验证；独立查询入口；Shodan 需配置 Key' if k=='shodan-python' else 'CLI 安装已验证；独立查询入口'})
counts={tool+'.'+status:0 for tool in ('blackbird','maigret','spiderfoot','theHarvester','shodan-python') for status in ('queued','running','succeeded','failed','cancelled','timed_out','interrupted')}
database=root/'state/jobs.sqlite'
if database.exists():
 with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as c:
  for tool,status,count in c.execute('SELECT tool,status,count(*) FROM jobs GROUP BY tool,status'): counts[tool+'.'+status]=count
# Java Properties loaded with a UTF-8 Reader. Values are generated from metadata, never credentials.
lines=['updated='+str(int(time.time())),'count='+str(len(items))]
for i,item in enumerate(items):
 for key,value in item.items():lines.append(f'item.{i}.{key}={str(value).replace(chr(10)," ").replace(chr(13)," ")}')
for key,value in counts.items():lines.append('osint.'+key+'='+str(value))
cm={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'petclinic-platform-snapshot','namespace':'petclinic','labels':{'app.kubernetes.io/part-of':'petclinic-observability'}},'data':{'snapshot.properties':'\n'.join(lines)+'\n'}}
subprocess.run(KUBE+['apply','-f','-'],input=json.dumps(cm),text=True,check=True,timeout=30)
print('Published',len(items),'software deployment records; OSINT aggregates only')
