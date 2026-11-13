"""Exact read-only Trivy version/DB metadata inspection. No scan, refresh, env dump or Secret."""
from pathlib import Path
import subprocess,shlex,json,datetime,os
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''set -eu
/usr/local/bin/trivy --version
sha256sum /usr/local/bin/trivy
for f in /home/scanner/.cache/trivy/db/metadata.json /home/scanner/.cache/trivy/java-db/metadata.json; do
 printf 'METADATA:%s\n' "$f"; cat "$f"; printf '\n'; sha256sum "$f"
done
for f in /home/scanner/.cache/trivy/db/trivy.db /home/scanner/.cache/trivy/java-db/trivy-java.db /home/scanner/.cache/trivy/fanal/fanal.db; do
 if [ -f "$f" ]; then stat -c '%n|%s|%b|%B|%d|%i|%Y' "$f"; fi
done
printf 'READ_ONLY_HEADER_SAMPLE\n'; od -An -tx1 -N 80 /home/scanner/.cache/trivy/db/trivy.db
printf 'OPTIONAL_INTEGRITY_TOOLS\n'; command -v bbolt || true; command -v bolt || true
printf 'TEMP_ENTRIES\n'; find /tmp -maxdepth 1 -name '*trivy*' -o -name 'oci-download-*'
'''
cmd='sudo -n kubectl exec -n harbor harbor-trivy-0 -c trivy -- sh -c '+shlex.quote(script)
p=subprocess.run(S+[cmd],capture_output=True,text=True,timeout=35);assert p.returncode==0,'Read-only DB inspection failed'
(O/'current-db-readonly.stdout').write_text(p.stdout)
metadata={}
lines=p.stdout.splitlines()
for i,line in enumerate(lines):
 if line.startswith('METADATA:'):metadata['java-db' if '/java-db/' in line else 'db']=json.loads(lines[i+1])
assert set(metadata)=={'db','java-db'}
x={'classification':'CURRENT_READ_ONLY_VERSION_AND_METADATA_NO_SCAN','sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'metadata':metadata,'fullDBIntegrity':'UNKNOWN_NOT_FULL_CHECKED','headerSampleOnly':True,'fullDBChecksumCalculated':False,'realScanCount':0,'dbRefreshCount':0}
(O/'current-db.json').write_text(json.dumps(x,indent=2)+'\n')
s=os.statvfs('/Users/zhangsir/code');(O/'local-backing-storage.json').write_text(json.dumps({'sampledAt':x['sampledAt'],'capacityBytes':s.f_blocks*s.f_frsize,'availableBytes':s.f_bavail*s.f_frsize,'inodeFree':s.f_favail,'classification':'MAC_BACKING_NOT_ADDITIONAL_GUEST_SPACE','COWPeakUpperBound':'UNKNOWN'},indent=2)+'\n')
print(json.dumps(x))
