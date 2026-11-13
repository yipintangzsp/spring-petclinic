from pathlib import Path
import hashlib,json,sys,datetime
O=Path(__file__).resolve().parent;phase=sys.argv[1];assert phase in ['before','after']
paths={'proxyConfig':Path('/Users/zhangsir/Library/Application Support/v2rayN/binConfigs/config.json'),'utmConfig':Path('/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/config.plist')}
result={}
for name,p in paths.items():
 result[name]={'path':str(p),'exists':p.is_file()}
 if p.is_file():
  b=p.read_bytes();s=p.stat();result[name].update({'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'mtimeNs':s.st_mtime_ns})
(O/('local-config-'+phase+'.json')).write_text(json.dumps({'classification':'READ_ONLY_HASH_NO_CONFIG_VALUES_EXPORTED','files':result,'writes':0},indent=2)+'\n');print('LOCAL_CONFIG_DIGESTS_RECORDED '+phase)
