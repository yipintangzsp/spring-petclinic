import pathlib,runpy,json,time
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');commit=json.loads((h/'prepared.json').read_text())['triggerCommit']
code=p['PREFIX']+r'''
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo'),b=d.getBuildByNumber(11)
def result=b?[build:11,result:b.result?.toString(),building:b.building,url:'http://jenkins.devops.local/job/security-gitlab-push-demo/11/',description:b.description,causes:b.getCauses().collect{it.class.name},logTail:b.getLog(14)]:[building:true,notStarted:true]
if(b&&!b.building){def f=new File(b.artifactsDir,'evidence/security-manager-result.json');if(f.exists())result.manager=new JsonSlurper().parseText(f.text)}
result.hooks=api('/projects/12/hooks/5/events').take(4).collect{e->[id:e.id,status:e.response_status,trigger:e.trigger,createdAt:e.created_at,commit:e.request_data?.after]}
println(JsonOutput.toJson(result))
'''
for n in range(12):
 x=p['script'](code)
 if not x['building']:break
 time.sleep(3)
with(h/'build11-observed.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
