"""Read-only PostgreSQL evidence. No Secret values or personal rows are emitted."""
import importlib.util,json,subprocess,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('audit',Path(__file__).parents[1]/'observability/audit-production.py'); a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
def sql(q,db='petclinic'):
 return subprocess.check_output(['ssh','-o','BatchMode=yes','192.168.1.58',f'sudo -n k3s kubectl exec -i -n ns-data deploy/postgresql -- psql -X -v ON_ERROR_STOP=1 -U postgres -d {db} -At'],input=q,text=True,timeout=60).strip()
queries={
 'version': 'SELECT version()',
 'settings': "SELECT name,setting FROM pg_settings WHERE name IN ('data_directory','max_connections','shared_buffers','work_mem','log_min_duration_statement','log_statement','log_duration','track_io_timing','shared_preload_libraries') ORDER BY name",
 'counts': "SELECT 'owners',count(*) FROM owners UNION ALL SELECT 'pets',count(*) FROM pets UNION ALL SELECT 'vets',count(*) FROM vets UNION ALL SELECT 'visits',count(*) FROM visits",
 'sizes': "SELECT tablename,pg_total_relation_size(format('%I.%I',schemaname,tablename)) FROM pg_tables WHERE schemaname='public'; SELECT pg_database_size(current_database())",
 'constraints': "SELECT conrelid::regclass,conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1,2",
 'indexes': "SELECT tablename,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname",
 'connections': 'SELECT datname,application_name,client_addr,state,count(*) FROM pg_stat_activity GROUP BY 1,2,3,4 ORDER BY 1,3',
 'databases': 'SELECT datname,numbackends,pg_database_size(datname) FROM pg_stat_database',
 'fingerprints': "SELECT 'owners',count(*),md5(string_agg(md5(row_to_json(t)::text),',' ORDER BY id)) FROM owners t WHERE id<1000000 UNION ALL SELECT 'pets',count(*),md5(string_agg(md5(row_to_json(t)::text),',' ORDER BY id)) FROM pets t WHERE id<1000000 UNION ALL SELECT 'vets',count(*),md5(string_agg(md5(row_to_json(t)::text),',' ORDER BY id)) FROM vets t WHERE id<1000000 UNION ALL SELECT 'visits',count(*),md5(string_agg(md5(row_to_json(t)::text),',' ORDER BY id)) FROM visits t WHERE id<1000000",
 'record': 'SELECT id,md5(row_to_json(t)::text) FROM owners t WHERE id=1',
 'orphans': 'SELECT count(*) FROM pets p LEFT JOIN owners o ON p.owner_id=o.id WHERE o.id IS NULL; SELECT count(*) FROM visits v LEFT JOIN pets p ON v.pet_id=p.id WHERE p.id IS NULL',
 'plans': "EXPLAIN (ANALYZE,BUFFERS) SELECT id FROM owners WHERE lower(first_name || ' ' || last_name) LIKE '%demo%' ORDER BY last_name LIMIT 5; EXPLAIN (ANALYZE,BUFFERS) SELECT * FROM pets WHERE owner_id=1000001; EXPLAIN (ANALYZE,BUFFERS) SELECT * FROM visits WHERE pet_id=1000001"
}
result={'time':a.datetime.now(a.timezone.utc).isoformat(),'sql':{k:sql(q) for k,q in queries.items()}}
for key,args in {'deployment':'-n ns-data get deployment postgresql','pods':'-n ns-data get pods -l app=postgresql','service':'-n ns-data get svc postgresql','pvc':'-n ns-data get pvc postgresql-data','storageclass':'get storageclass local-path','nodes':'get nodes','all_pods':'get pods -A'}.items():
 d=a.kube(args)
 # Strip literal environment values from other workloads; references remain auditable.
 if key=='all_pods':
  for p in d['items']:
   for c in p['spec'].get('containers',[])+p['spec'].get('initContainers',[]):
    c.pop('env',None);c.pop('envFrom',None);c.pop('args',None);c.pop('command',None)
 result[key]=d
result['pv']=a.kube('get pv '+result['pvc']['spec']['volumeName'])
result['registry_tables']=sql("SELECT schemaname,tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')",'registry')
cm=a.kube('-n data-infra get cm trino-catalog')
result['other_dependency']={k:[line for line in v.splitlines() if 'connection-url' in line or 'connector.name' in line] for k,v in cm['data'].items()}
result['postgres_log_summary']=a.remote("sudo -n k3s kubectl logs -n ns-data deploy/postgresql --tail=300 | python3 -c \"import sys,collections; x=sys.stdin.read().splitlines(); print(dict(collections.Counter(k for k in ['ERROR','FATAL','PANIC','WARNING','ready to accept connections'] for l in x if k in l)))\"")
Path(sys.argv[1]).write_text(json.dumps(result,indent=2));print(json.dumps({'sql':result['sql'],'shared_dependency':result['other_dependency'],'logs':result['postgres_log_summary']},indent=2))
