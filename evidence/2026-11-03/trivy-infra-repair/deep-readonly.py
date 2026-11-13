from pathlib import Path
import subprocess,json,concurrent.futures
O=Path(__file__).resolve().parent;S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
commands={
'home-usage':'sudo -n timeout 50s ionice -c3 nice -n19 du -x -B1 --max-depth=2 /home/zhang',
'jenkins-usage':'sudo -n timeout 50s ionice -c3 nice -n19 du -x -B1 --max-depth=2 /var/lib/rancher/k3s/storage/pvc-14c139bf-5717-4b2f-9997-4c77fa03f409_ns-devops_jenkins-pvc',
'config-references':"sudo -n find /opt /etc/systemd/system /home/zhang -xdev -maxdepth 4 -type f \\( -name 'compose*.yml' -o -name 'docker-compose*.yml' -o -name '*.service' -o -name 'values*.yaml' \\) -print",
'docker-mounts':"sudo -n docker ps -aq | xargs -r sudo -n docker inspect --format '{{json .Name}} {{json .Config.Image}} {{json .Mounts}}'",
'helm':'sudo -n helm list -A -o json',
'argo':'sudo -n kubectl get applications -n argocd -o custom-columns=NAME:.metadata.name,REPO:.spec.source.repoURL,PATH:.spec.source.path,REVISION:.status.sync.revision'
}
def run(item):
 n,c=item;p=subprocess.run(S+[c],capture_output=True,text=True,timeout=60);(O/(n+'.stdout')).write_text(p.stdout);(O/(n+'-execution.json')).write_text(json.dumps({'command':c,'exit':p.returncode,'stderr':p.stderr[-1500:]},indent=2));return {'name':n,'exit':p.returncode,'bytes':len(p.stdout)}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
 for r in ex.map(run,commands.items()):print(json.dumps(r),flush=True)
