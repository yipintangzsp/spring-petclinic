from pathlib import Path
import subprocess,json,shlex,sys,urllib.parse,base64,hashlib
O=Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(a):
 p=subprocess.run(S+['sudo -n kubectl '+shlex.join(a)],capture_output=True,text=True,timeout=30);assert p.returncode==0,'READ_ONLY_KUBE_FAILED';return json.loads(p.stdout)
app=k(['-n','argocd','get','application','petclinic','-o','json']);(O/'application-current.json').write_text(json.dumps(app,indent=2)+'\n')
for name,args in [('deployment-current',['-n','petclinic','get','deployment','petclinic']),('service-current',['-n','petclinic','get','service','petclinic']),('ingress-current',['-n','petclinic','get','ingress','petclinic'])]:(O/(name+'.json')).write_text(json.dumps(k(args+['-o','json']),indent=2)+'\n')
revision=app['status']['sync']['revision'];assert len(revision)==40
# Only public manifests and source/config metadata. Never export Secret resources or credential values.
script='''import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
def c=CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class,Jenkins.instance,null,null).find{it.id=='gitlab-creds'};assert c!=null
String token=c.password.plainText
def base='http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/'+java.net.URLEncoder.encode('root/petclinic-platform','UTF-8')
def get={p->def conn=new URL(base+p).openConnection();conn.setRequestProperty('PRIVATE-TOKEN',token);conn.connectTimeout=10000;conn.readTimeout=15000;assert conn.responseCode==200;conn.inputStream.getText('UTF-8')}
def enc={s->java.net.URLEncoder.encode(s,'UTF-8')}
def rev=REVISION
def tree=new groovy.json.JsonSlurperClassic().parseText(get('/repository/tree?path=k8s%2Fproduction&per_page=100&ref='+rev))
def names=['petclinic.yaml','petclinic-configmap.yaml','petclinic-pdb.yaml','petclinic-servicemonitor.yaml','petclinic-prometheusrule.yaml','petclinic-harbor-alias.yaml']
def files=tree.findAll{x->names.contains(x.name)||x.name.contains('dashboard')}.collectEntries{x->[(x.path):get('/repository/files/'+enc(x.path)+'/raw?ref='+rev).bytes.encodeBase64().toString()]}
def j=Jenkins.instance.getItemByFullName('petclinic-ci'),b=j.lastBuild
def p=new ProcessBuilder('sh','-c','command -v helm || true; helm version --short 2>/dev/null || true; uname -m; command -v python3 || true; python3 -c "import yaml;print(yaml.__version__)" 2>/dev/null || true').redirectErrorStream(true).start();def tool=p.inputStream.getText('UTF-8');p.waitFor()
println(JsonOutput.toJson([gitOpsRevision:rev,filesBase64:files,productionBuild:b.number,productionResult:b.result.toString(),jobScriptPath:j.definition.scriptPath,jobBranches:j.definition.scm.branches.collect{it.name},nodeTooling:tool]))
'''.replace('REVISION',json.dumps(revision))
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':120000}
p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=135);assert p.returncode==0,'JENKINS_READ_ONLY_FAILED';res=json.loads(p.stdout);assert res['status']==200,'JENKINS_DISCOVERY_HTTP_'+str(res['status']);x=json.loads(res['body'].split('\n',1)[0]);files=x.pop('filesBase64');out=O/'gitops-baseline';out.mkdir(exist_ok=True);identities={}
for path,content in files.items():
 data=base64.b64decode(content);assert b'kind: Secret\n' not in data,'Secret resource not safe to archive';p=out/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);identities[path]=hashlib.sha256(data).hexdigest()
x['files']=identities;x['argoSource']=app['spec']['source'];x['destination']=app['spec']['destination'];x['argoResources']=app['status'].get('resources');x['classification']='READ_ONLY_LIVE_GITOPS_AND_PIPELINE_DISCOVERY';(O/'discovery.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
