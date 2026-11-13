from pathlib import Path
import json,hashlib,datetime,subprocess,sys,os
from analysis_semantics import parse,canonical_digest,exposure
O=Path(__file__).resolve().parent;label=sys.argv[1];assert label in ['T0','T1','T2','T3']
root=Path('/Users/zhangsir/Library/Application Support/v2rayN');rows=[];summary={}
for name,p in [('runtimeGenerated',root/'binConfigs/config.json'),('guiSourceMutable',root/'guiConfigs/guiNConfig.json')]:
 b=p.read_bytes();x=parse(b.decode('utf-8-sig'));s=p.stat();rows.append({'name':name,'path':str(p),'rawSha256':hashlib.sha256(b).hexdigest(),'allFieldsCanonicalAnalysisDigest':canonical_digest(x),'bytes':len(b),'mtimeNs':s.st_mtime_ns,'inode':s.st_ino,'analysisOnlyNotCheckpointHash':True,'excludedFields':[]})
 if name=='runtimeGenerated':
  inbound=[{'tag':i.get('tag'),'listen':i.get('listen'),'port':i.get('port'),'protocol':i.get('protocol'),'authenticationMode':i.get('settings',{}).get('auth'),'accountsPresent':bool(i.get('settings',{}).get('accounts')),'sniffingDigest':canonical_digest(i.get('sniffing'))} for i in x.get('inbounds',[])]
  outbound=[{'tag':o.get('tag'),'protocol':o.get('protocol'),'identityDigest':canonical_digest({'settings':o.get('settings'),'streamSettings':o.get('streamSettings'),'proxySettings':o.get('proxySettings'),'mux':o.get('mux')}),'security':o.get('streamSettings',{}).get('security')} for o in x.get('outbounds',[])]
  summary={'inbounds':inbound,'lanExposure':exposure(x.get('inbounds',[])),'routingMode':x.get('routing',{}).get('domainStrategy'),'routingRulesDigest':canonical_digest(x.get('routing',{}).get('rules')),'outbounds':outbound,'dnsDigest':canonical_digest(x.get('dns')),'policyDigest':canonical_digest(x.get('policy')),'allRootKeys':list(x)}
# Active listeners only. No curl/traffic generation; no core command invoked.
p=subprocess.run(['lsof','-nP','-a','-p','6529','-iTCP','-sTCP:LISTEN'],capture_output=True,text=True,timeout=10)
result={'sample':label,'sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':rows,'activeRuntimeSummary':summary,'mainXrayPid':6529,'listenerOutput':p.stdout,'listenerCheckExit':p.returncode,'historicalSemanticsBaselineAvailable':False,'notAnAcceptanceWindow':True}
(O/('observation-'+label+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'sample':label,'runtimeSha256':rows[0]['rawSha256'],'analysisDigest':rows[0]['allFieldsCanonicalAnalysisDigest'],'guiSha256':rows[1]['rawSha256'],'inbounds':summary['inbounds'],'lanExposure':summary['lanExposure']}))
