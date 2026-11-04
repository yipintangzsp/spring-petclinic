import pathlib,subprocess,json,os,hashlib,shutil,errno,datetime
assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime(2026,11,4,5,4,tzinfo=datetime.timezone.utc)
try:
 acl=os.getxattr('/run/docker.sock','system.posix_acl_access');raise RuntimeError('NAMED_ACL_REQUIRES_REVIEW')
except OSError as e:assert e.errno in [errno.ENODATA,errno.ENOTSUP],str(e)
root=pathlib.Path('/var/backups/docker-socket-change-20261104-1234');root.mkdir(mode=0o700,exist_ok=False)
files=['/etc/systemd/system/docker.service.d/override.conf','/etc/systemd/system/docker.service.d/limits.conf','/usr/lib/systemd/system/docker.socket']
for f in files:shutil.copy2(f,root/pathlib.Path(f).name)
s=os.stat('/run/docker.sock');state={'uid':s.st_uid,'gid':s.st_gid,'mode':oct(s.st_mode&0o777),'ino':s.st_ino,'extendedAccessACL':'ABSENT','independentSSHRecovery':'root via existing authorized sudo; does not depend on Jenkins or Docker API'}
(root/'socket-state.json').write_text(json.dumps(state));os.chmod(root/'socket-state.json',0o600)
d=json.loads(subprocess.check_output(['kubectl','get','deployment','jenkins','-n','ns-devops','-o','json']))
(root/'jenkins-security-context.json').write_text(json.dumps({'uid':d['metadata']['uid'],'securityContext':d['spec']['template']['spec'].get('securityContext',{}),'resourceVersion':d['metadata']['resourceVersion']}));os.chmod(root/'jenkins-security-context.json',0o600)
restore='sudo cp -a '+str(root)+'/override.conf /etc/systemd/system/docker.service.d/override.conf\nsudo systemctl daemon-reload\n# ONLY authorized emergency rollback when needed:\nsudo chmod 0666 /run/docker.sock\n# Restore Jenkins supplementalGroups via exact original field, after access is restored. Never restart Docker.\n'
(root/'RESTORE.txt').write_text(restore);os.chmod(root/'RESTORE.txt',0o600)
hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in root.iterdir() if f.is_file()};(root/'sha256.json').write_text(json.dumps(hashes,indent=2));os.chmod(root/'sha256.json',0o600)
print(json.dumps({'backupDirectory':str(root),'directoryMode':oct(root.stat().st_mode&0o777),'hashes':hashes,'socketState':state,'productionConfigurationModified':False},indent=2))
