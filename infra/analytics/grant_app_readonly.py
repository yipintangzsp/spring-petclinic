"""Grant the existing application role access to stored summaries, never raw facts."""
import shlex
from controlled import remote

CODE = r'''import base64,json,subprocess
secret=json.loads(subprocess.check_output(['kubectl','-n','petclinic','get','secret','petclinic-db','-o','json']))
role=base64.b64decode(secret['data']['POSTGRES_USER']).decode()
assert role and len(role)<64 and '\x00' not in role
quoted='"'+role.replace('"','""')+'"'
sql='GRANT USAGE ON SCHEMA petclinic_analytics TO '+quoted+'; GRANT SELECT ON petclinic_analytics.runs,petclinic_analytics.daily_visits,petclinic_analytics.pet_types,petclinic_analytics.executions TO '+quoted+';'
p=subprocess.run(['kubectl','-n','ns-data','exec','deploy/postgresql','--','psql','-U','postgres','-d','petclinic','-v','ON_ERROR_STOP=1','-Atc',sql],capture_output=True,text=True,timeout=20)
if p.returncode:raise RuntimeError('Summary read grant failed')
print(json.dumps({'summary_read_granted':True,'tables':['runs','daily_visits','pet_types','executions']}))
'''

if __name__ == '__main__':
    print(remote('sudo -n python3 -c '+shlex.quote(CODE)))
