"""Pure supplemental-review validator. Never contacts a host, runs a scanner or authorizes execution."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator
CATEGORIES={'PRODUCTION_REQUIRED','VALIDATION_ONLY','OPTIONAL','NOT_REQUIRED','UNKNOWN'}
PROXY_NODES={'prod-v2rayN','prod-xray','prod-loopback','prod-lan-proxy','prod-proxy-continuity'}
class ReviewError(ValueError):pass

def validate_graph(g):
 if g.get('schemaVersion')!=1 or g.get('productionProxyRequired') not in {'YES','NO','UNKNOWN'}:raise ReviewError('GRAPH_HEADER')
 nodes=g.get('nodes',[]);ids=[x.get('id') for x in nodes]
 if not nodes or len(set(ids))!=len(ids) or g.get('root') not in ids:raise ReviewError('GRAPH_IDENTITY')
 lookup={x['id']:x for x in nodes};edges=g.get('edges',[]);adj={x:[] for x in ids}
 for x in nodes:
  if x.get('classification') not in CATEGORIES or type(x.get('requiredForExperiment')) is not bool or not x.get('sealedSource') or not x.get('rationale'):raise ReviewError('NODE_EVIDENCE')
 for e in edges:
  if e.get('from') not in lookup or e.get('to') not in lookup:raise ReviewError('EDGE_REFERENCE')
  adj[e['from']].append(e['to'])
 seen=set();active=set()
 def walk(x):
  if x in active:raise ReviewError('DEPENDENCY_CYCLE')
  if x in seen:return
  active.add(x)
  for y in adj[x]:walk(y)
  active.remove(x);seen.add(x)
 walk(g['root'])
 if not PROXY_NODES<=set(ids):raise ReviewError('MISSING_PROXY_REVIEW')
 if g['productionProxyRequired']=='NO':
  if seen & PROXY_NODES:raise ReviewError('FALSE_PROXY_INDEPENDENCE')
  if any(lookup[x]['classification']=='PRODUCTION_REQUIRED' for x in seen):raise ReviewError('PRODUCTION_EDGE_IN_ISOLATED_DESIGN')
  if any(lookup[x]['requiredForExperiment'] or lookup[x]['classification']!='NOT_REQUIRED' for x in PROXY_NODES):raise ReviewError('CONTRADICTORY_PROXY_NODE')
 return {'validated':True,'reachable':sorted(seen)}

def evaluate_preflight(doc,schema):
 Draft202012Validator(schema).validate(doc)
 if not doc['targetId'] or doc['networkMode']=='NOT_SELECTED':return False
 return all(v['status']=='VERIFIED' and isinstance(v['evidenceRef'],str) and bool(v['evidenceRef'].strip()) for v in doc['checks'].values())

def evaluate_gates(design_checks,graph,continuity,preflight,schema):
 validate_graph(graph)
 if not isinstance(design_checks,dict) or not design_checks or any(type(v) is not bool for v in design_checks.values()):raise ReviewError('DESIGN_CHECKS_INVALID')
 if continuity not in {'VERIFIED','BROKEN','NOT_PROVEN'}:raise ReviewError('CONTINUITY_INVALID')
 design=all(design_checks.values());ready=evaluate_preflight(preflight,schema)
 proxy=graph['productionProxyRequired']
 # A failed production continuity gate affects isolated execution ONLY if actual proxy dependency exists.
 execution=design and ready and (proxy=='NO' or (proxy=='YES' and continuity=='VERIFIED'))
 case=3 if not design else 1 if proxy=='NO' and not execution else 2 if proxy=='YES' and continuity!='VERIFIED' else None
 return {'DESIGN_COMPLETENESS':'READY' if design else 'NOT_READY','PRODUCTION_CHECKPOINT_CONTINUITY':continuity,'EXPERIMENT_EXECUTION_GATE':'READY' if execution else 'NOT_READY','decisionMatrixCase':case,'executionAuthorizedByThisReview':False}
