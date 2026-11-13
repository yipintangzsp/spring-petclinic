import runpy,json,sys,shlex,urllib.parse,pathlib,datetime
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
groovy='''import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import jenkins.model.GlobalNodePropertiesConfiguration
def rows=[]
def add={where,domains->domains.each{domain,credentials->credentials.each{c->
 def u=c.metaClass.hasProperty(c,'username')?c.username?.toLowerCase():''
 def d=c.description?.toLowerCase()?:''
 rows.add([id:c.id,store:where,type:c.getClass().simpleName,grafanaMetadataHint:d.contains('grafana')||u?.contains('grafana')||u?.contains('editor'),administratorUsername:u in ['admin','root','administrator'],valuesRead:false])
}}}
add('SYSTEM',SystemCredentialsProvider.getInstance().getDomainCredentialsMap())
Jenkins.instance.allItems.findAll{it.getClass().name.contains('Folder')}.each{folder->
 CredentialsProvider.lookupStores(folder).each{store->store.domains.each{domain->add(folder.fullName,[(domain):store.getCredentials(domain)])}}
}
def globals=[]
Jenkins.instance.globalNodeProperties.each{p->if(p.metaClass.hasProperty(p,'envVars'))globals.addAll(p.envVars.keySet().findAll{it.toUpperCase().contains('GRAFANA')||it.startsWith('GF_')})}
println(JsonOutput.toJson([metadata:rows,grafanaGlobalEnvironmentNames:globals,credentialValuesRead:0,mutations:0]))'''
p={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':groovy}),'timeout':20000}
r=json.loads(api['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps(p),45));assert r['status']==200
x=json.loads(r['body'].split('\n')[0]);x['at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
with pathlib.Path('evidence/2026-11-06/grafana-non-admin-discovery/jenkins-metadata-followup.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
