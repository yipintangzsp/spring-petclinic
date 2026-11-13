from pathlib import Path
import subprocess,json,shlex
O=Path(__file__).resolve().parent;S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];code=r'''
import subprocess,json
p=subprocess.run(['sudo','-n','k3s','ctr','-n','k8s.io','containers','list'],capture_output=True,text=True,timeout=20)
assert p.returncode==0
matches=[x for x in p.stdout.splitlines() if 'mirrored-pause' in x or 'mirrored-library-busybox' in x]
print(json.dumps({'scope':'containerd actual container metadata including pod sandboxes','matchingKnownImageRows':matches,'rawOutputNotPersisted':True,'writes':0}))
''';p=subprocess.run(S+['python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=30);assert p.returncode==0;x=json.loads(p.stdout);(O/'runtime-hidden-reference-proof.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'matchingRuntimeRows':len(x['matchingKnownImageRows']),'pauseRows':sum('mirrored-pause' in x for x in x['matchingKnownImageRows']),'busyboxRows':sum('mirrored-library-busybox' in x for x in x['matchingKnownImageRows'])}))
