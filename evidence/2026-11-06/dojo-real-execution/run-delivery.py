import sys,pathlib,tempfile,json,subprocess,os
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'grafana-v2-real'));from keychain_store import operation
# Credential exists only in owned temporary storage required by existing adapter; always removed.
with tempfile.TemporaryDirectory(prefix='dojo-demo-credential-')as private:
 secret=pathlib.Path(private)/'token';token=operation('get',service='petclinic-security-manager-v2-defectdojo',account='security-manager-v2-demo')
 fd=os.open(secret,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'w')as f:f.write(token)
 del token
 privateRoot=pathlib.Path('.devsecops/dojo-demo-java-v1').resolve();privateRoot.mkdir(mode=0o700,exist_ok=True)
 for n in ['journal','output']:(privateRoot/n).mkdir(mode=0o700,exist_ok=True)
 try:
  p=subprocess.run(['node',str(HERE/'deliver.mjs')],input=json.dumps({'credentialFile':str(secret.resolve()),'journalDirectory':str(privateRoot/'journal'),'output':str(privateRoot/'output'),'evidence':str(HERE)}),text=True,capture_output=True,timeout=160)
  print(p.stdout);print(p.stderr[-1600:]);raise SystemExit(p.returncode)
 finally:secret.unlink(missing_ok=True)
