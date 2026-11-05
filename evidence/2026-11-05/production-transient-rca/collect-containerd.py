import pathlib,json,datetime,os,re,subprocess
start='2026-11-05T02:05:00';end='2026-11-05T02:45:00';r={'classification':'READ_ONLY_EXISTING_EMBEDDED_CONTAINERD_LOG','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'windowStart':start+'Z','windowEnd':end+'Z','files':[],'productionMutations':0}
root=pathlib.Path('/var/lib/rancher/k3s/agent/containerd');files=sorted(root.glob('containerd.log*'),key=lambda p:p.stat().st_mtime,reverse=True)[:2]
for p in files:
 s=p.stat();offset=max(0,s.st_size-2*1024*1024)
 with p.open('rb')as f:f.seek(offset);raw=f.read(2*1024*1024)
 lines=raw.decode(errors='replace').splitlines();kept=[];times=[]
 for line in lines:
  m=re.search(r'time="([^"]+)"',line)
  if not m:continue
  t=m.group(1);times.append(t)
  try:d=datetime.datetime.fromisoformat(t.replace('Z','+00:00')).astimezone(datetime.timezone.utc).isoformat()
  except ValueError:continue
  if start<=d[:19]<=end:kept.append(line[:4000])
 r['files'].append({'path':str(p),'size':s.st_size,'mtime':datetime.datetime.fromtimestamp(s.st_mtime,datetime.timezone.utc).isoformat(),'readOffset':offset,'readBytes':len(raw),'partialFile':offset>0,'tailFirstSourceTimestamp':min(times,default=None),'tailLastSourceTimestamp':max(times,default=None),'windowLines':kept})
r['virtualization']=subprocess.run(['systemd-detect-virt'],text=True,capture_output=True).stdout.strip()
print(json.dumps(r))
