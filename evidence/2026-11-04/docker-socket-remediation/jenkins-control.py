import pathlib,sys,json,subprocess,shlex,urllib.parse,hashlib
sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
p=pathlib.Path(__file__).parent;phase=sys.argv[1]
common="""import groovy.json.JsonOutput
import java.security.MessageDigest
def x=Jenkins.instance
def busy=x.computers.collectMany{it.allExecutors}.findAll{it.busy}.collect{[number:it.number,task:it.currentExecutable?.toString()]}
def jobs=x.allItems.findAll{it.metaClass.respondsTo(it,'makeDisabled',Boolean.TYPE)}
"""
if phase in ['preflight','final']:
 script=common+"""def b=x.getItemByFullName('petclinic-ci').getBuildByNumber(270)
def f=new File(b.artifactsDir,'.devsecops/security-summary.json')
println(JsonOutput.toJson([busy:busy,queue:x.queue.items.collect{it.task.fullDisplayName},quiet:x.quietingDown,jobs:jobs.collect{[name:it.fullName,disabled:it.disabled,building:it.lastBuild?.building]},historical:[build:270,result:b.result.toString(),summarySha256:MessageDigest.getInstance('SHA-256').digest(f.bytes).encodeHex().toString()]]))
"""
elif phase=='pause':
 prior=json.loads((p/'jenkins-preflight.json').read_text());names=[j['name'] for j in prior['jobs'] if not j['disabled']];assert not prior['busy'] and not prior['queue'] and not prior['quiet']
 script=common+"""if(new Date().after(Date.from(java.time.Instant.parse('2026-11-04T05:04:00Z'))))throw new Exception('WINDOW_CLOSED')
x.doQuietDown()
def currentBusy=x.computers.collectMany{it.allExecutors}.any{it.busy}
if(currentBusy || x.queue.items){x.doCancelQuietDown();throw new Exception('BUSY_OR_QUEUED_STOP')}
"""+'def names='+json.dumps(names)+"\nnames.each{n->x.getItemByFullName(n).makeDisabled(true)}\nx.doQuietDown()\nprintln(JsonOutput.toJson([paused:names,quiet:x.quietingDown,busy:busy,queue:x.queue.items.size()]))"
elif phase=='resume':
 prior=json.loads((p/'jenkins-preflight.json').read_text());names=[j['name'] for j in prior['jobs'] if not j['disabled']]
 script=common+'x.doQuietDown()\ndef names='+json.dumps(names)+"\nnames.each{n->x.getItemByFullName(n).makeDisabled(false)}\nx.doCancelQuietDown()\nprintln(JsonOutput.toJson([restored:names,quiet:x.quietingDown,jobs:jobs.collect{[name:it.fullName,disabled:it.disabled]}]))"
else:raise SystemExit('unknown phase')
args=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58','sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)]
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000}
r=subprocess.run(args,input=json.dumps(payload),capture_output=True,text=True,timeout=70);assert r.returncode==0,r.stderr[-500:];response=json.loads(r.stdout);assert response['status']==200
body=response['body'].strip()
if not body.startswith('{'):(p/('jenkins-'+phase+'-error.txt')).write_text(body[:2500]);raise SystemExit('Jenkins operation rejected')
d=json.loads(body.split('\n')[0]);(p/('jenkins-'+phase+'.json')).write_text(json.dumps(d,indent=2));print(json.dumps(d))
