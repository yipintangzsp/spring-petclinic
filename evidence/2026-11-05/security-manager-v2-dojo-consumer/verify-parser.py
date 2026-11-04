"""Installed parser source, isolated model doubles: format compatibility ONLY.

No Django app setup, database, API client, Token or actual import pipeline.
"""
from pathlib import Path
import ast,json,hashlib,math,copy
O=Path(__file__).resolve().parent
source=O/'installed-dojo-parser/dojo/tools/generic/json_parser.py';inspection=json.loads((O/'installed-parser-inspection.json').read_text());expected=inspection['files']['dojo/tools/generic/json_parser.py']['sha256'];assert hashlib.sha256(source.read_bytes()).hexdigest()==expected
module=ast.parse(source.read_text());nodes=[]
for n in module.body:
 if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='NUMERIC_FIELDS'for t in n.targets):nodes.append(n)
 elif isinstance(n,ast.FunctionDef)and n.name=='to_number':nodes.append(n)
 elif isinstance(n,ast.ClassDef)and n.name=='GenericJSONParser':nodes.append(n)
class Finding:
 def __init__(self,**kw):self.__dict__.update(kw);self.cve=None;self.unsaved_vulnerability_ids=[]
class ParserTest:
 def __init__(self,**kw):self.__dict__.update(kw)
def unique(findings):
 ids=[f.unique_id_from_tool for f in findings];assert len(ids)==len(set(ids))
namespace={'math':math,'Finding':Finding,'ParserTest':ParserTest,'locations_enabled':lambda:False,'_finding_max_lengths':lambda:{},'mark_unique_ids_ambiguous_when_repeated':unique}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),namespace)
parser=namespace['GenericJSONParser']();checks=[]
for file in sorted((O/'samples').glob('*/*.generic.json')):
 payload=json.loads(file.read_text());original=copy.deepcopy(payload);test=parser._get_test_json(copy.deepcopy(payload));assert len(test.findings)==len(payload['findings'])
 for f,p in zip(test.findings,payload['findings']):
  assert all(getattr(f,k)==v for k,v in p.items())
 assert payload==original
 checks.append({'file':str(file.relative_to(O)),'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'findings':len(test.findings),'installedParserFieldAndNumericPath':'PASS'})
nonempty=next(json.loads(p.read_text())for p in (O/'samples').glob('*/*.generic.json')if json.loads(p.read_text())['findings']);negatives=[]
for name,mutate in [('missing-required',lambda p:p['findings'][0].pop('severity')),('unknown-field',lambda p:p['findings'][0].update({'arbitrary_token':'SYNTHETIC_NOT_REAL'}))]:
 value=copy.deepcopy(nonempty);mutate(value)
 try:parser._get_test_json(value)
 except ValueError as e:negatives.append({'name':name,'status':'REJECTED_BY_INSTALLED_PARSER_LOGIC','reason':str(e)})
 else:raise AssertionError('Parser accepted malformed payload')
result={'classification':'OFFLINE_INSTALLED_PARSER_LOGIC_WITH_DJANGO_MODEL_DOUBLES','instanceVersion':'3.4.301','parserSha256':expected,'checks':checks,'negativeChecks':negatives,'databaseModelValidation':'NOT_TESTED','databaseColumnWidths':'NOT_TESTED_MODEL_DOUBLES_USED','importAPI':'NOT_TESTED','remoteDelivery':'NOT_TESTED','remoteIdempotency':'NOT_TESTED','tokenRead':False,'httpRequests':0,'note':'This proves payload field/numeric contract against installed code, NOT a DefectDojo server acceptance or DB import.'}
with(O/'parser-compatibility.json').open('x')as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps({'payloads':len(checks),'negativeChecks':len(negatives),'format':'PASS','remoteDelivery':'NOT_TESTED'}))
