from pathlib import Path
import sqlite3,json,hashlib,urllib.parse,datetime
O=Path(__file__).resolve().parent;root=Path('/Users/zhangsir/Library/Application Support/v2rayN');db=root/'guiConfigs/guiNDB.db';cfg=json.load(open(root/'guiConfigs/guiNConfig.json'));sha=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
con=sqlite3.connect('file:'+urllib.parse.quote(str(db))+'?mode=ro&immutable=1',uri=True);con.row_factory=sqlite3.Row
schema={row['name']:[x['name'] for x in con.execute('pragma table_info('+row['name']+')')] for row in con.execute("select name from sqlite_master where type='table' and name in ('ProfileItem','SubItem','RoutingItem','StatisticsItem')")}
rows=[]
if 'SubItem' in schema:
 for x in con.execute('select * from SubItem'):
  d=dict(x);public={k:v for k,v in d.items() if k.lower() in ['enable','enabled','autoupdateinterval','updateinterval','autoupdate','isautoupdate','updatetime','lastupdatetime','lastupdated','issort']};rows.append({'rowIdentitySha256':sha(d.get('Id',d.get('IndexId'))),'urlPresent':bool(d.get('Url')),'subscriptionSourceIdentitySha256':sha(d.get('Url')) if d.get('Url') else None,'configuredBehavior':public})
selected=None
if 'ProfileItem' in schema and 'IndexId' in schema['ProfileItem']:
 row=con.execute('select * from ProfileItem where IndexId=?',(cfg.get('IndexId'),)).fetchone()
 if row:
  d=dict(row);selected={'selectedIndexSha256':sha(cfg.get('IndexId')),'recordExists':True,'schemaOnlyFields':list(d),'publicTypeFields':{k:v for k,v in d.items() if k in ['ConfigType','CoreType','Security','Network','StreamSecurity','AllowInsecure','Fingerprint']},'selectedIdentityDigest':sha(d),'subscriptionIdDigest':sha(d.get('Subid',d.get('SubId'))),'privateNodeValuesArchived':False}
con.close();out={'classification':'READ_ONLY_IMMUTABLE_SQLITE_NO_SOURCE_WRITES','schema':schema,'subscriptionBehaviors':rows,'selectedProfile':selected,'databaseMtimeNsAtRead':db.stat().st_mtime_ns,'fullDBContentHashNotAssumedStable':True,'guiExtraSafeSettings':{'CoreBasicItem.Keys':list(cfg.get('CoreBasicItem',{})),'GuiItem.Keys':list(cfg.get('GuiItem',{})),'GuiItem.AutoUpdateInterval':cfg.get('GuiItem',{}).get('AutoUpdateInterval'),'RoutingBasicItem.Keys':list(cfg.get('RoutingBasicItem',{})),'Inbound':[{k:v for k,v in row.items() if k in ['LocalPort','Protocol','Listen','UdpEnabled','SniffingEnabled','AllowLANConn','NewPort4LAN']} for row in cfg.get('Inbound',[])]}}
(O/'source-db-settings.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'tableColumns':schema,'subscriptionCount':len(rows),'subscriptionBehaviorFields':[r['configuredBehavior'] for r in rows],'selectedPublicTypes':selected.get('publicTypeFields') if selected else None,'guiExtraSafeSettings':out['guiExtraSafeSettings']}))
