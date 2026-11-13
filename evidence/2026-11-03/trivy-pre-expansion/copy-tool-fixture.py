from pathlib import Path
import tempfile,os,subprocess,hashlib,json,shutil
O=Path(__file__).resolve().parent;root=Path(tempfile.mkdtemp(prefix='vm-copy-fixture-',dir='/private/tmp'));result={'scope':'DISPOSABLE_SYNTHETIC_HOST_COPY_TOOL_TEST_NOT_VM_BACKUP','productionImageRead':False,'backupCreated':False,'filesystem':'APFS same host volume only; external target not tested','command':['rsync','-aS','--extended-attributes','SOURCE_FIXTURE','DESTINATION_FIXTURE']}
try:
 source=root/'source';dest=root/'destination';source.mkdir();dest.mkdir();s=source/'source.fixture';d=dest/'source.fixture'
 with s.open('wb') as f:f.truncate(64*1024**2);f.seek(0);f.write(b'X'*4096);f.seek(64*1024**2-4096);f.write(b'Y'*4096)
 s.chmod(0o600);os.utime(s,(1670000000,1670000000));subprocess.run(['xattr','-w','com.codex.vmbackup.fixture','disposable',str(s)],check=True,capture_output=True)
 r=subprocess.run(['rsync','-aS','--extended-attributes',str(source)+'/',str(dest)+'/'],capture_output=True,text=True,timeout=15);result['exitStatus']=r.returncode;result['stderr']=r.stderr[:500]
 if r.returncode==0:
  hashfile=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();a=s.stat();b=d.stat();attr=subprocess.run(['xattr','-p','com.codex.vmbackup.fixture',str(d)],capture_output=True,text=True)
  result.update({'sourceLogicalBytes':a.st_size,'destinationLogicalBytes':b.st_size,'sourceAllocatedBytes':a.st_blocks*512,'destinationAllocatedBytes':b.st_blocks*512,'hashMatches':hashfile(s)==hashfile(d),'modePreserved':(a.st_mode&0o777)==(b.st_mode&0o777),'mtimePreserved':a.st_mtime==b.st_mtime,'xattrPreserved':attr.returncode==0 and attr.stdout.strip()=='disposable','distinctInodes':a.st_ino!=b.st_ino})
  with d.open('r+b') as f:f.write(b'Z')
  with s.open('rb') as f:result['sourceUnaffectedByDestinationWrite']=f.read(1)==b'X'
  result['sparseCopyObserved']=b.st_blocks*512<1024*1024;result['verifiedScope']='Small synthetic same-APFS file copy only; NOT consistency/restore proof for a VM or external filesystem'
except Exception as e:result['errorClass']=type(e).__name__;result['error']='Disposable copy tool test failed; original VM never read or written'
finally:shutil.rmtree(root);result['temporaryFilesRemoved']=not root.exists()
(O/'copy-tool-fixture.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
