from pathlib import Path
import runpy,tempfile,sys,json
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;b=runpy.run_path(str(O/'http-boundary.py'))
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve()
 code='''import socket,json,threading
from pathlib import Path
r={}
for port in [32185,32187]:
 s=socket.socket();s.bind(('127.0.0.1',port));s.listen(1)
 def serve():
  c,a=s.accept();c.send(b'ok');c.close()
 th=threading.Thread(target=serve);th.start();c=socket.create_connection(('127.0.0.1',port),1);r[str(port)]=c.recv(2).decode();c.close();th.join();s.close()
for name,address in [('otherLoopback',('127.0.0.1',32188)),('external',('192.0.2.1',80))]:
 try:socket.create_connection(address,1);r[name]='ALLOWED'
 except PermissionError:r[name]='DENIED'
 except Exception:r[name]='UNKNOWN'
try:Path(CANARY).write_text('bad');r['protectedWrite']='ALLOWED'
except PermissionError:r['protectedWrite']='DENIED'
print(json.dumps(r))
'''
 p=b['guarded'](t,[sys.executable,'-B','-c','CANARY='+repr(str(O/'owned-boundary-canary-r2.txt'))+'\n'+code]);assert p.returncode==0,p.stderr
 checks=json.loads(p.stdout);assert checks=={'32185':'ok','32187':'ok','otherLoopback':'DENIED','external':'DENIED','protectedWrite':'DENIED'},checks
r={'classification':'REAL_OS_FILESYSTEM_AND_TWO_PORT_NETWORK_BOUNDARY','checks':checks,'historicalWriteProbes':0,'temporaryTreeRemoved':not Path(d).exists()}
with(O/'http-boundary-preflight.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n')
print(json.dumps(r))
