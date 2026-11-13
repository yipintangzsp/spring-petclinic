"""Apply reviewed additive analytics DDL separately from the limited business role."""
import argparse
import datetime as dt
import json
import shlex
from pathlib import Path

from controlled import jenkins, kube, remote

CODE = r'''import base64,json,subprocess,sys
schema=sys.stdin.read()
secret=json.loads(subprocess.check_output(['kubectl','-n','data-infra','get','secret','petclinic-analysis-db','-o','json']))
role=base64.b64decode(secret['data']['ANALYTICS_DB_USER']).decode()
assert role and len(role)<64 and '\x00' not in role
quoted='"'+role.replace('"','""')+'"'
sql="SET lock_timeout='3s'; SET statement_timeout='15s';\n"+schema+'\nGRANT SELECT,INSERT,UPDATE ON petclinic_analytics.executions TO '+quoted+';'
p=subprocess.run(['kubectl','-n','ns-data','exec','-i','deploy/postgresql','--','psql','-U','postgres','-d','petclinic','--single-transaction','-v','ON_ERROR_STOP=1'],input=sql,capture_output=True,text=True,timeout=40)
if p.returncode:raise RuntimeError('Analysis migration failed: '+p.stderr[-500:])
print(json.dumps({'schema_applied':True,'public_tables_changed':False,'execution_grants':['SELECT','INSERT','UPDATE'],'analysis_role_ddl_granted':False}))
'''


def migrate(evidence):
    evidence = Path(evidence); evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
    if any((job.get('lastBuild') or {}).get('building') for job in state.get('jobs', [])):
        raise RuntimeError('Finish the release before applying its reviewed analytics migration')
    if any(item['metadata']['name'] == 'platform-heavy' for item in
           kube(['-n', 'data-infra', 'get', 'leases', '-o', 'json'])['items']):
        raise RuntimeError('Finish the owned heavy run before applying the analytics migration')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')
    backup = remote('sudo -n kubectl -n ns-data exec deploy/postgresql -- pg_dump -U postgres -d petclinic --schema=petclinic_analytics --no-owner --no-privileges', timeout=40)
    path = evidence / ('analytics-before-' + stamp + '.sql')
    path.write_text(backup); path.chmod(0o600)
    result = remote('sudo -n python3 -c ' + shlex.quote(CODE),
                    Path(__file__).with_name('schema.sql').read_text(), timeout=50)
    (evidence / ('migration-' + stamp + '.json')).write_text(result)
    print(result.strip())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    migrate(parser.parse_args().evidence)
