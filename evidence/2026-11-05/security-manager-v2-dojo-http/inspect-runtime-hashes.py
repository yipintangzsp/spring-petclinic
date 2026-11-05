from pathlib import Path
import runpy,json,sys
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'));phase=sys.argv[1];assert phase in ['before-final-tests','final']
code=r'''
import json,hashlib,pathlib,subprocess
files=['/opt/defectdojo/compose.json']
config={str(pathlib.Path(n)):hashlib.sha256(pathlib.Path(n).read_bytes()).hexdigest() for n in files}
args=['kubectl','-n','harbor','exec','harbor-trivy-0','-c','trivy','--','sh','-c','for f in /home/scanner/.cache/trivy/db/trivy.db /home/scanner/.cache/trivy/java-db/trivy-java.db; do stat -c "%n|%s|%i|%Y" "$f"; sha256sum "$f"; done']
r=subprocess.run(args,text=True,capture_output=True,timeout=120)
print(json.dumps({'classification':'REAL_READ_ONLY_STREAMING_DATABASE_HASH_NOT_SCANNER_EXECUTION','databaseHashCommandExit':r.returncode,'trivyDatabaseHashesAndStats':r.stdout,'trivyDiagnosticCode':None if r.returncode==0 else 'HASH_UNAVAILABLE','dojoComposeSha256':config,'credentialReads':0,'writes':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,150));api['save']('runtime-hashes-'+phase+'.json',x);print(json.dumps(x))
