"""Prove revocation of only this task's temporary project token after baseline restoration."""
from common import *
assert OUT.name=='attempt2'
final=json.loads((OUT/'final-check.json').read_text());assert final['host']['demo']['value']=='baseline'
identity=json.loads((BASE/'identity.json').read_text());tokenid=identity['tokenId']
code=p['PREFIX']+r'''
def list=api('/projects/12/access_tokens')
def token=list.find{it.id==@ID@};assert token && token.name=='security-gitops-demo-20261106' && token.access_level==30 && token.scopes==['write_repository']
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/access_tokens/@ID@').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='DELETE';c.connectTimeout=4000;c.readTimeout=6000
assert c.responseCode==204:'Task token revoke failed'
println(JsonOutput.toJson([tokenId:@ID@,revoked:true,http:204,productionCredentialsChanged:false]))
'''.replace('@ID@',str(tokenid))
r=script(code)
host=r'''
import pathlib,json,urllib.request,urllib.error,base64,os
home=pathlib.Path('/var/lib/security-gitops-demo');meta=json.loads((home/'identity-metadata.json').read_text());f=home/'git-token';assert f.stat().st_uid==24022
token=f.read_text();url='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git/info/refs?service=git-receive-pack'
req=urllib.request.Request(url,headers={'Authorization':'Basic '+base64.b64encode(('oauth2:'+token).encode()).decode()})
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=8) as r:status=r.status
except urllib.error.HTTPError as e:status=e.code
assert status in [401,403],'Revoked token still authorized'
f.unlink()
print(json.dumps({'revokedTokenReceivePackHttp':status,'taskTokenFileRemoved':not f.exists(),'productionSecretRead':False}))
'''
h=remote(host,25);r.update(h);save('revocation.json',r);print(json.dumps(r))
