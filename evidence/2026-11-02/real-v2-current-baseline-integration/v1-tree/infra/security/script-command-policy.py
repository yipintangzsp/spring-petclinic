"""Narrow intra-procedural shell policy; unknown wrappers/aliases stay unproven."""
import ast
SINKS={'subprocess.run','subprocess.call','subprocess.check_call','subprocess.check_output','subprocess.Popen','os.system','os.popen','eval','exec'}
def inspect_python(source,path='<fixture>'):
 tree=ast.parse(source);findings=[]
 shadowed={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}|{n.arg for n in ast.walk(tree) if isinstance(n,ast.arg)}|{n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 imported_sys=any(isinstance(n,ast.Import) and any(a.name=='sys' and not a.asname for a in n.names) for n in tree.body)
 flask_request=any(isinstance(n,ast.ImportFrom) and n.module=='flask' and any(a.name=='request' and not a.asname for a in n.names) for n in tree.body)
 def value(n,env):
  if n is None:return set()
  if isinstance(n,ast.Name):return env.get(n.id,set())
  if isinstance(n,ast.Subscript) and imported_sys and 'sys' not in shadowed and ast.unparse(n.value)=='sys.argv':return {'external'}
  if isinstance(n,ast.Call):
   name=ast.unparse(n.func)
   if name=='input' and 'input' not in shadowed or flask_request and 'request' not in shadowed and name in ('request.args.get','request.form.get'):return {'external'}
   if name in ('os.getenv','os.environ.get'):return {'unknown_environment'}
   if name=='shlex.quote':return {'quoted'} if n.args and 'external' in value(n.args[0],env) else set()
  return set().union(*(value(x,env) for x in ast.iter_child_nodes(n)))
 def block(statements,env):
  for st in statements:
   if isinstance(st,(ast.FunctionDef,ast.AsyncFunctionDef)):
    block(st.body,{});continue
   if isinstance(st,ast.ClassDef):block(st.body,{});continue
   # Clear only a constant-string membership check which rejects all nonmembers.
   if isinstance(st,ast.If) and isinstance(st.test,ast.Compare) and len(st.test.ops)==1 and isinstance(st.test.ops[0],ast.NotIn) and isinstance(st.test.left,ast.Name) and isinstance(st.test.comparators[0],(ast.Tuple,ast.List,ast.Set)) and st.test.comparators[0].elts and all(isinstance(x,ast.Constant) and isinstance(x.value,str) for x in st.test.comparators[0].elts) and len(st.body)==1 and isinstance(st.body[0],(ast.Raise,ast.Return)) and not st.orelse:
    env[st.test.left.id]=set();continue
   for n in ast.walk(st):
    if not isinstance(n,ast.Call):continue
    name=ast.unparse(n.func)
    if name not in SINKS:continue
    arg=n.args[0] if n.args else next((k.value for k in n.keywords if k.arg=='args'),None)
    shell=any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in n.keywords)
    if name.startswith('subprocess.') and not shell:continue
    if isinstance(arg,(ast.List,ast.Tuple)):continue
    flow=value(arg,env)
    if 'external' in flow and not flow.intersection({'quoted','unknown_environment'}):findings.append({'path':path,'line':n.lineno,'rule':'python-unvalidated-external-shell','severity':'HIGH','source':'input/sys.argv or explicit Flask request parameter','sink':name,'reason':'external source reaches shell/interpreter string without recognized constant allowlist or quoting','action':'FAIL'})
   if isinstance(st,ast.Assign):
    flow=value(st.value,env)
    for target in st.targets:
     if isinstance(target,ast.Name):env[target.id]=flow
   if isinstance(st,ast.AnnAssign) and isinstance(st.target,ast.Name):env[st.target.id]=value(st.value,env)
   # Do not infer sanitization or definite flows across conditionals/loops/wrappers.
   if isinstance(st,(ast.If,ast.For,ast.While,ast.Try,ast.With)):
    for attr in ['body','orelse','finalbody']:
     nested=getattr(st,attr,[])
     if nested:block(nested,dict(env))
 block(tree.body,{})
 # Nested statement walks can repeat a call; reports retain one actual location.
 return list({(x['path'],x['line'],x['sink']):x for x in findings}.values())

def self_test():
 positive=['import os\nos.system(input())','import subprocess\nx=input()\nsubprocess.run("echo "+x,shell=True)','import sys,os\nx=sys.argv[1]\nos.system(x)','from flask import request\nimport os\nx=request.args.get("cmd")\nos.system(x)']
 negative=['import subprocess\nsubprocess.run(["echo",input()])','import os\nos.system("date")','import os\nx=input()\nif x not in ("date","uptime"):\n raise ValueError()\nos.system(x)','import subprocess,shlex\nx=input()\nsubprocess.run("echo "+shlex.quote(x),shell=True)','import os\nx=os.getenv("ADMIN_COMMAND")\nos.system(x)']
 for source in positive:assert inspect_python(source),source
 for source in negative:assert not inspect_python(source),source
 assert not inspect_python('import os\ndef input(): return \"date\"\nos.system(input())')
 return {'external_shell_detected':len(positive),'safe_or_unproven_not_blocked':len(negative),'executed_commands':0}
