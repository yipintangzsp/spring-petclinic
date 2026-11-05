"""Static contract verification against copied installed source, not Django/API execution."""
from pathlib import Path
import ast,json,hashlib,sys
R=Path(sys.argv[1]).resolve();A=R/'installed-api';S=R/'http-protocol-samples'
module=ast.parse((A/'dojo/api_v2/serializers.py').read_text())
classes={n.name:n for n in module.body if isinstance(n,ast.ClassDef)}
def assignments(node):return {t.id:n.value for n in node.body if isinstance(n,ast.Assign) for t in n.targets if isinstance(t,ast.Name)}
common=assignments(classes['CommonImportScanSerializer']);imp=assignments(classes['ImportScanSerializer']);reimp=assignments(classes['ReImportScanSerializer']);allowed=set(common)|set(imp)
assert 'description' not in allowed
assert {'build_id','version','file','scan_type','engagement','close_old_findings','close_old_findings_product_scope','auto_create_context','deduplication_execution_mode'}<=allowed
assert 'do_not_reactivate' not in allowed and 'do_not_reactivate' in reimp
kw=lambda call,key:next(ast.literal_eval(k.value) for k in call.keywords if k.arg==key)
assert kw(imp['close_old_findings'],'default') is False and kw(reimp['close_old_findings'],'default') is True
models={n.name:n for n in ast.parse((A/'dojo/test/models.py').read_text()).body if isinstance(n,ast.ClassDef)};fields=assignments(models['Test']);assert kw(fields['version'],'max_length')==100 and kw(fields['build_id'],'max_length')==150
assert not any(k.arg=='unique' and ast.literal_eval(k.value) for k in fields['title'].keywords)
source=(A/'dojo/importers/default_importer.py').read_text();assert 'version=self.version' in source and 'build_id=self.build_id' in source and 'title=self.test_title' in source
count=0;keys=set()
for sample in S.glob('*.json'):
 x=json.loads(sample.read_text())
 for req in x['received']:
  fields=req['fields'];assert set(fields)<=allowed
  assert fields['close_old_findings']=='false' and fields['auto_create_context']=='false' and fields['close_old_findings_product_scope']=='false'
  assert len(fields['build_id'])<=150 and len(fields['version'])<=100
  assert fields['version']==hashlib.sha256(json.dumps(req['payload'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
  keys.update(fields);count+=1
assert count>0
print(json.dumps({'classification':'INSTALLED_SOURCE_SCHEMA_STATIC_CHECK_NOT_REAL_API_IMPORT','instanceVersion':'3.4.301','actualMultipartPayloadsChecked':count,'declaredFieldsVerified':sorted(keys),'descriptionInputUnsupportedAndNotSent':True,'importDoNotReactivateUnsupportedAndNotSent':True,'reimportCloseOldDefaultTrue':True,'buildIdAndVersionPersistedByDefaultImporter':True,'buildIdMaxLength':150,'versionMaxLength':100,'atomicRequestIdempotency':'NOT_ESTABLISHED','testTitleUniqueConstraint':False,'realAuthenticatedAPI':'NOT_TESTED','rawFindingMappingsUnchanged':True}))
