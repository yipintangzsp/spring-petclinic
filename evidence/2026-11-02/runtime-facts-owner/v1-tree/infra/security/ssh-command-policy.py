"""Narrow, local flow check for reviewed SSH wrapper call sites; never runs SSH."""
import ast,hashlib
WRAPPERS={'infra/analytics/controlled.py':'command','infra/observability/audit-production.py':'command'}
INTERPRETERS={'sh','bash','dash','zsh','python','python3','node','ssh','eval'}
def inspect_ssh(source,path='<fixture>'):
 tree=ast.parse(source);findings=[];calls=[]
 imports={a.asname or a.name for n in tree.body if isinstance(n,ast.ImportFrom) and n.module in ('controlled','infra.analytics.controlled') for a in n.names if a.name=='remote'}
 # Dynamically loaded audit.remote aliases are inventoried but not automatically promoted.
 dynamic_aliases={n.targets[0].id for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Call) and ast.unparse(n.value.func).endswith('module_from_spec')}
 has_sys=any(isinstance(n,ast.Import) and any(a.name=='sys' and not a.asname for a in n.names) for n in tree.body)
 has_request=any(isinstance(n,ast.ImportFrom) and n.module=='flask' and any(a.name=='request' and not a.asname for a in n.names) for n in tree.body)
 shadowed={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}|{n.arg for n in ast.walk(tree) if isinstance(n,ast.arg)}|{n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 def flow(n,env):
  if n is None or isinstance(n,ast.Constant):return set()
  if isinstance(n,ast.Name):return env.get(n.id,{'unknown'})
  if isinstance(n,ast.Subscript) and has_sys and 'sys' not in shadowed and ast.unparse(n.value)=='sys.argv':return {'external'}
  if isinstance(n,ast.Call):
   name=ast.unparse(n.func)
   if name=='input' and 'input' not in shadowed or has_request and 'request' not in shadowed and name in ('request.args.get','request.form.get'):return {'external'}
   if name in ('os.getenv','os.environ.get') or name.endswith(('.read','.read_text','.get_json')):return {'unknown'}
   if name=='shlex.quote':return {'escaped'}
   if name=='shlex.join' and n.args and isinstance(n.args[0],(ast.List,ast.Tuple)) and n.args[0].elts:
    parts=n.args[0].elts;first=parts[0]
    if isinstance(first,ast.Constant) and isinstance(first.value,str) and first.value in {'printf','echo','date','uptime','true','false'}:return {'escaped'}
    # A nested interpreter or dynamic executable is not granted a quoting bypass.
    return {'unknown'}
  return set().union(*(flow(c,env) for c in ast.iter_child_nodes(n)))
 def visit(body,env):
  for st in body:
   if isinstance(st,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):visit(st.body,{});continue
   if isinstance(st,ast.If) and isinstance(st.test,ast.Compare) and len(st.test.ops)==1 and isinstance(st.test.ops[0],ast.NotIn) and isinstance(st.test.left,ast.Name) and isinstance(st.test.comparators[0],(ast.Tuple,ast.List,ast.Set)) and st.test.comparators[0].elts and all(isinstance(x,ast.Constant) and isinstance(x.value,str) for x in st.test.comparators[0].elts) and len(st.body)==1 and isinstance(st.body[0],(ast.Raise,ast.Return)) and not st.orelse:
    env[st.test.left.id]=set();continue
   for n in ast.walk(st):
    if not isinstance(n,ast.Call):continue
    name=ast.unparse(n.func);arg=None;proven=False;kind=None
    if isinstance(n.func,ast.Name) and name in imports and name not in shadowed:
     arg=n.args[0] if n.args else next((k.value for k in n.keywords if k.arg=='command'),None);proven=True;kind='controlled.remote'
    elif isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id in dynamic_aliases and n.func.attr=='remote':
     arg=n.args[0] if n.args else None;kind='dynamic-loaded remote alias'
    elif name in ('subprocess.run','subprocess.check_output','subprocess.Popen') and n.args and isinstance(n.args[0],(ast.List,ast.Tuple)):
     parts=n.args[0].elts
     if len(parts)==3 and isinstance(parts[0],ast.Constant) and parts[0].value=='ssh' and isinstance(parts[1],ast.Constant) and isinstance(parts[1].value,str) and not parts[1].value.startswith('-'):
      arg=parts[2];proven=True;kind='direct fixed-host ssh argv'
    if kind is None:continue
    taint=flow(arg,env);classification='external_controllable' if 'external' in taint else 'unknown' if 'unknown' in taint else 'dynamic_controlled' if taint else 'fixed_trusted'
    high=proven and taint=={'external'}
    row={'path':path,'line':n.lineno,'wrapper':kind,'classification':classification,'source_evidence':sorted(taint),'action':'FAIL' if high else 'WARN' if classification in ('unknown','external_controllable') else 'reviewed_nonblocking','rule':'ssh-unvalidated-external-command' if high else None}
    calls.append(row)
    if high:findings.append(row)
   if isinstance(st,ast.Assign):
    v=flow(st.value,env)
    for t in st.targets:
     if isinstance(t,ast.Name):env[t.id]=v
   if isinstance(st,(ast.If,ast.For,ast.While,ast.Try,ast.With)):
    for attr in ('body','orelse','finalbody'):
     if getattr(st,attr,None):visit(getattr(st,attr),dict(env))
 visit(tree.body,{})
 unique=lambda xs:list({(x['path'],x['line'],x['wrapper']):x for x in xs}.values())
 return {'findings':unique(findings),'calls':unique(calls)}
def self_test():
 positive=['from controlled import remote\nremote("echo "+input())','import sys\nfrom controlled import remote\nx=sys.argv[1]\nremote(x)','from flask import request\nfrom controlled import remote\nx=request.args.get("cmd")\nremote(x)','import subprocess\nsubprocess.run(["ssh","fixed-host","echo "+input()])']
 negative=['from controlled import remote\nremote("uptime")','import shlex\nfrom controlled import remote\nremote(shlex.join(["printf","%s",input()]))','import shlex\nfrom controlled import remote\nremote("printf %s "+shlex.quote(input()))','from controlled import remote\nx=input()\nif x not in ("date","uptime"):\n raise ValueError()\nremote(x)','import os\nfrom controlled import remote\nremote(os.getenv("ADMIN_COMMAND"))','from pathlib import Path\nfrom controlled import remote\nremote(Path("operator-command").read_text())','import subprocess\nsubprocess.run(["echo",input()])']
 for s in positive:assert inspect_ssh(s)['findings'],s
 for s in negative:assert not inspect_ssh(s)['findings'],s
 return {'external_ssh_detected':len(positive),'safe_or_unproven_not_blocked':len(negative),'executed_commands':0}
def analyze(files):
 selftests=self_test();calls=[];blocking=[];bindings={}
 for path,source in files.items():
  if path.endswith('.py'):
   r=inspect_ssh(source,path);calls+=r['calls'];blocking+=r['findings']
  if path in WRAPPERS:bindings[path]=hashlib.sha256(source.encode()).hexdigest()
 return {'status':'failed' if blocking else 'success','wrapper_source_sha256':bindings,'calls':calls,'blockingFindings':blocking,'counts':{k:sum(x['classification']==k for x in calls) for k in ('fixed_trusted','dynamic_controlled','external_controllable','unknown')},'tests':selftests,'scope':'two reviewed SSH wrappers and fixed-host direct SSH; local explicit source flows only; runtime import resolution, general SSH options, environment/file/message provenance and cross-function flow remain WARN'}
