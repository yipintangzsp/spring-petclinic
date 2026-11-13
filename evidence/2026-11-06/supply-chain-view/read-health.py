import ast,pathlib,runpy,json
HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
tree=ast.parse((HERE.parent/'grafana-v2-real/health.py').read_text());code=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in n.targets))
x=json.loads(api['remote']('sudo -n python3 -',code,75));old=json.loads((HERE.parent/'dojo-real-execution/production-health.json').read_text())
x['configurationUnchanged']=all(x[k]==old[k]for k in ['deploymentSpecSha256','argoSpecSha256','generation','argoRevision','socketMode']);x['health']='HEALTHY'if x['ready']==3 and x['http']==200 and x['argoSync']=='Synced'and x['argoHealth']=='Healthy'and all(n['ready']=='True'for n in x['nodes'])else'DEGRADED'
with(HERE/'production-health.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps({'health':x['health'],'configurationUnchanged':x['configurationUnchanged'],'runningImageIds':[p['imageIds']for p in x['pods']]}))
