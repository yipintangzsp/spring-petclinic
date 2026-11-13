from pathlib import Path
import subprocess,json,concurrent.futures,datetime
O=Path(__file__).resolve().parent;S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
commands={
'block-topology':'lsblk -b -J -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS,PKNAME,MODEL,SERIAL,START; sudo -n sfdisk --json /dev/vda; sudo -n blkid; findmnt -J -T /; df -B1 -T /; df -i /',
'geometry':'sudo -n fdisk -l /dev/vda; command -v parted; command -v growpart; command -v resize2fs; sudo -n blockdev --getsize64 /dev/vda; sudo -n blockdev --getss /dev/vda; cat /proc/mdstat; command -v pvs; sudo -n pvs --reportformat json 2>/dev/null; systemd-detect-virt',
'filesystem-health':'sudo -n tune2fs -l /dev/vda2; sudo -n journalctl -k --since "24 hours ago" --no-pager -o short-iso | grep -Ei "I/O error|EXT4-fs error|XFS.*error|Buffer I/O|corrupt|disk failure|blk_update_request|critical medium error|Remounting filesystem read-only"; true',
'filesystem-state':'sudo -n kubectl get --raw /api/v1/nodes/devops/proxy/stats/summary',
}
def run(item):
 name,cmd=item;p=subprocess.run(S+[cmd],capture_output=True,text=True,timeout=35)
 if name=='filesystem-state' and p.returncode==0:
  x=json.loads(p.stdout)['node'];out=json.dumps({'nodeName':x['nodeName'],'fs':x['fs'],'imageFs':x['runtime']['imageFs']},indent=2)
 else:out=p.stdout
 (O/(name+'.stdout')).write_text(out);(O/(name+'-execution.json')).write_text(json.dumps({'command':cmd,'exit':p.returncode,'stderr':p.stderr[-2000:],'collectedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2));return {'name':name,'exit':p.returncode,'bytes':len(out)}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
 for r in ex.map(run,commands.items()):print(json.dumps(r),flush=True)
