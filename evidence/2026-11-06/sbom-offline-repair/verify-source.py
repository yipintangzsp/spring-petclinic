import pathlib,json,runpy,shlex,sys
sys.dont_write_bytecode=True
here=pathlib.Path(__file__).resolve().parent;x=json.loads((here/'private-cache-preflight.json').read_text());assert x['status']=='VERIFIED'
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import pathlib,hashlib,urllib.request,concurrent.futures,json,sys,time
items=json.load(sys.stdin);root=pathlib.Path('/var/lib/security-sbom/repository')
def check(i):
 p=i['path'];assert '..'not in pathlib.PurePosixPath(p).parts and not p.startswith('/')and p.endswith(('.jar','.pom'))
 b=(root/p).read_bytes();assert hashlib.sha256(b).hexdigest()==i['sha256']
 with urllib.request.urlopen('https://repo.maven.apache.org/maven2/'+p+'.sha1',timeout=10)as r:expected=r.read(200).decode().strip().split()[0]
 if hashlib.sha1(b).hexdigest()!=expected:raise RuntimeError('OFFICIAL_CHECKSUM_MISMATCH '+p)
 return {**i,'officialChecksumAlgorithm':'SHA1_OVER_HTTPS','officialChecksum':expected,'source':'https://repo.maven.apache.org/maven2/'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:verified=list(pool.map(check,items))
print(json.dumps({'status':'VERIFIED','artifacts':verified,'verifiedCount':len(verified),'generationCount':0,'credentialsUsed':False}))
'''
r=json.loads(api['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(x['resolvedArtifacts']),timeout=200))
with(here/'official-artifact-checksums.json').open('x')as f:json.dump(r,f,indent=2)
print(json.dumps({'status':r['status'],'verifiedCount':r['verifiedCount'],'generationCount':0}))
