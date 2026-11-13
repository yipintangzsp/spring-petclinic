import json,runpy,urllib.request,urllib.error,pathlib,socket,datetime
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import urllib.request,urllib.error,json
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));rows=[]
for url in ['http://127.0.0.1:18095/login','http://192.168.64.11:18095/login']:
 try:
  with op.open(url,timeout=4)as r:rows.append({'url':url,'status':r.status,'finalUrl':r.geturl()})
 except urllib.error.HTTPError as e:rows.append({'url':url,'status':e.code})
 except Exception as e:rows.append({'url':url,'status':'UNREACHABLE','errorClass':type(e).__name__})
print(json.dumps(rows))
'''
x={'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'serverHTTP':json.loads(api['remote']('python3 -',code,25)),'macHTTP':[]}
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for url in ['http://192.168.64.11:18095/login','http://defectdojo.devops.local/login']:
 try:
  with op.open(url,timeout=4)as r:x['macHTTP'].append({'url':url,'status':r.status,'finalUrl':r.geturl()})
 except urllib.error.HTTPError as e:x['macHTTP'].append({'url':url,'status':e.code})
 except Exception as e:x['macHTTP'].append({'url':url,'status':'UNREACHABLE','errorClass':type(e).__name__})
with pathlib.Path('evidence/2026-11-06/dojo-real-delivery/http.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
