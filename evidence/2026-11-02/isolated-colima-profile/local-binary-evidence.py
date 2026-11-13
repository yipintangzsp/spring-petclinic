"""Read installed Colima's Go metadata and disassemble only config helper functions.
No Colima startup, VM, network, installation or target binary code execution.
"""
from pathlib import Path
import struct,subprocess,json,hashlib
OUT=Path(__file__).resolve().parent
p=Path('/opt/homebrew/Cellar/colima/0.10.3/bin/colima');d=p.read_bytes();off=32;sections={}
assert struct.unpack_from('<I',d,0)[0]==0xfeedfacf
for _ in range(struct.unpack_from('<I',d,16)[0]):
 cmd,size=struct.unpack_from('<II',d,off)
 if cmd==0x19:
  for i in range(struct.unpack_from('<I',d,off+64)[0]):
   s=off+72+i*80;name=d[s:s+16].split(b'\0')[0].decode();sections[name]=struct.unpack_from('<QQI',d,s+32)
 off+=size
h=sections['__gopclntab'][2];assert struct.unpack_from('<I',d,h)[0]==0xfffffff1
nfunc,_,_,names,*rest=struct.unpack_from('<QQQQQQQQ',d,h+8);ft=h+rest[-1];base=sections['__text'][0]
wanted={'github.com/abiosoft/colima/config.Config.MountsOrDefault','github.com/abiosoft/colima/cmd.mountsFromFlag','github.com/abiosoft/colima/config.ProfileFromName','github.com/abiosoft/colima/config.(*Profile).ConfigDir'};found=[]
for i in range(nfunc):
 entry,fo=struct.unpack_from('<II',d,ft+8*i);no=struct.unpack_from('<i',d,ft+fo+4)[0];start=h+names+no;name=d[start:d.find(b'\0',start)].decode(errors='replace')
 if name not in wanted:continue
 end=struct.unpack_from('<I',d,ft+8*(i+1))[0];a=base+entry;z=base+end
 args=['/Library/Developer/CommandLineTools/usr/bin/llvm-objdump','--disassemble','--no-show-raw-insn','--start-address='+hex(a),'--stop-address='+hex(z),str(p)]
 r=subprocess.run(args,capture_output=True,text=True,timeout=15);assert r.returncode==0
 found.append({'function':name,'start':hex(a),'end':hex(z),'assembly':r.stdout})
assert {x['function'] for x in found}==wanted
(OUT/'local-binary-functions.json').write_text(json.dumps({'source':str(p),'sha256':hashlib.sha256(d).hexdigest(),'classification':'STATIC_READ_ONLY_CURRENT_INSTALLED_BINARY','functions':found,'mountConclusion':'CLI mountsFromFlag compares none and returns nil slice. Config.MountsOrDefault returns nil unchanged; only a non-nil zero-length slice gets HOME default. Explicit YAML mounts:null preserves nil; mounts:[] is unsafe default-home behavior.'},indent=2)+'\n')
print('Saved static installed-version config-helper evidence; no start executed')
