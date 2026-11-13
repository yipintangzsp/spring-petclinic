"""Derive only OCI launch metadata from the installed, cached Spark runtime."""
import json,shlex
from controlled import remote

CODE=r'''import json,urllib.request,urllib.parse,hashlib,datetime
base='http'+'://127.0.0.1:30050';source='platform-upgrade/kubeflow-spark-operator-controller';target='platform-upgrade/spark-runtime';tag='4.0.1-existing';original='sha256:68f4d74790b9a3a06f6b1ac5a5414c4b0b25c68b20ea68e8f8d87132e3a398f5'
accept='application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'
with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+source+'/manifests/'+original,headers={'Accept':accept}),timeout=10) as response:
 raw=response.read();assert 'sha256:'+hashlib.sha256(raw).hexdigest()==original;manifest=json.loads(raw)
config=json.load(urllib.request.urlopen(base+'/v2/'+source+'/blobs/'+manifest['config']['digest'],timeout=10))
assert config['architecture']=='arm64' and any('spark-4.0.1' in e for e in config['config']['Env'])
old_config=manifest['config']['digest'];old_entrypoint=config['config'].get('Entrypoint')
config['config']['Entrypoint']=['/opt/entrypoint.sh'];config['config']['Cmd']=None
config['config'].setdefault('Labels',{}).update({'petclinic.spark.version':'4.0.1','petclinic.base.manifest':original})
config.setdefault('history',[]).append({'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'created_by':'Use original installed Spark entrypoint; no filesystem change','empty_layer':True})
blob=json.dumps(config,separators=(',',':')).encode();digest='sha256:'+hashlib.sha256(blob).hexdigest()
# Mount original blobs inside the same existing registry; no layers are downloaded or rebuilt.
for layer in manifest['layers']:
 url=base+'/v2/'+target+'/blobs/uploads/?'+urllib.parse.urlencode({'mount':layer['digest'],'from':source})
 with urllib.request.urlopen(urllib.request.Request(url,data=b'',method='POST'),timeout=10) as response:
  assert response.status==201,'Existing registry did not mount the original layer'
with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+target+'/blobs/uploads/',data=b'',method='POST'),timeout=10) as response:
 location=urllib.parse.urljoin(base,response.headers['Location'])
url=location+('&' if '?' in location else '?')+urllib.parse.urlencode({'digest':digest})
with urllib.request.urlopen(urllib.request.Request(url,data=blob,method='PUT',headers={'Content-Type':'application/octet-stream'}),timeout=10) as response:assert response.status==201
manifest['config'].update({'digest':digest,'size':len(blob)});body=json.dumps(manifest,separators=(',',':')).encode();final='sha256:'+hashlib.sha256(body).hexdigest()
with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+target+'/manifests/'+tag,data=body,method='PUT',headers={'Content-Type':manifest['mediaType']}),timeout=10) as response:
 assert response.status==201 and response.headers.get('Docker-Content-Digest')==final
print(json.dumps({'image':target+'@'+final,'baseManifest':original,'baseConfig':old_config,'newConfig':digest,'previousEntrypoint':old_entrypoint,'newEntrypoint':['/opt/entrypoint.sh'],'architecture':'arm64','sparkVersion':'4.0.1','filesystemLayersUnchanged':[l['digest'] for l in manifest['layers']]}))
'''

if __name__=='__main__':
    print(remote('python3 -c '+shlex.quote(CODE),timeout=90))
