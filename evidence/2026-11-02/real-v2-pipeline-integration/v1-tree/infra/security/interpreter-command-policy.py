"""Explicit local external-input flow into interpreter code; no execution or broad sanitizer claims."""
import ast,re
INTERPRETERS={'sh':{'-c','-lc'},'bash':{'-c','-lc'},'dash':{'-c'},'python':{'-c'},'python3':{'-c'},'node':{'-e','--eval'}}
PROCESS={'subprocess.run','subprocess.call','subprocess.check_call','subprocess.check_output','subprocess.Popen'}
def inspect_source(source,path='<fixture>'):
 if not path.endswith('.py') and path!='<fixture>':
  return {'findings':[],'calls':[{'path':path,'line':i,'kind':'non-Python interpreter inventory','classification':'unknown','action':'WARN'} for i,l in enumerate(source.splitlines(),1) if re.search(r"['\"](?:sh|bash|python3?|node)['\"].*(?:['\"]-c['\"]|['\"]-lc['\"]|['\"]-e['\"])",l) and not l.lstrip().startswith(('#','//'))]}
 tree=ast.parse(source);calls=[];findings=[]
 has_sys=any(isinstance(n,ast.Import) and any(a.name=='sys' and not a.asname for a in n.names) for n in tree.body)
 request=any(isinstance(n,ast.ImportFrom) and n.module=='flask' and any(a.name=='request' and not a.asname for a in n.names) for n in tree.body)
 remote={a.asname or a.name for n in tree.body if isinstance(n,ast.ImportFrom) and n.module=='controlled' for a in n.names if a.name=='remote'}
 shadowed={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}|{n.arg for n in ast.walk(tree) if isinstance(n,ast.arg)}|{n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 def flow(n,env,code=False):
  if n is None or isinstance(n,ast.Constant):return set()
  if isinstance(n,ast.Name):return env.get(n.id,{'unknown'})
  if isinstance(n,ast.Subscript) and has_sys and 'sys' not in shadowed and ast.unparse(n.value)=='sys.argv':return {'external'}
  if isinstance(n,ast.Call):
   name=ast.unparse(n.func)
   if name=='input' and 'input' not in shadowed or request and 'request' not in shadowed and name in ('request.args.get','request.form.get'):return {'external'}
   if name=='shlex.quote':return {'unknown'} if code else {'escaped'}
   return {'unknown'}
  return set().union(*(flow(x,env,code) for x in ast.iter_child_nodes(n)))
 def emit(n,arg,env,kind,proven):
  f=flow(arg,env,True);high=proven and f=={'external'}
  row={'path':path,'line':n.lineno,'kind':kind,'classification':'external_controllable' if 'external'in f else 'unknown'if'unknown'in f else'dynamic_controlled'if f else'fixed_trusted','source':sorted(f),'action':'FAIL'if high else'WARN'if f else'reviewed_nonblocking','rule':'external-input-interpreter-code'if high else None}
  calls.append(row)
  if high:findings.append(row)
 def code_arg(argv):
  if not isinstance(argv,(ast.List,ast.Tuple)) or len(argv.elts)<3:return None
  a=argv.elts
  if not isinstance(a[0],ast.Constant) or not isinstance(a[0].value,str):return None
  first=a[0].value.rsplit('/',1)[-1]
  if first not in INTERPRETERS or not isinstance(a[1],ast.Constant) or a[1].value not in INTERPRETERS[first]:return None
  return a[2]
 def walk(body,env):
  for st in body:
   if isinstance(st,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):walk(st.body,{});continue
   if isinstance(st,ast.If) and isinstance(st.test,ast.Compare) and len(st.test.ops)==1 and isinstance(st.test.ops[0],ast.NotIn) and isinstance(st.test.left,ast.Name) and isinstance(st.test.comparators[0],(ast.Tuple,ast.List,ast.Set)) and st.test.comparators[0].elts and all(isinstance(x,ast.Constant) and isinstance(x.value,str) for x in st.test.comparators[0].elts) and len(st.body)==1 and isinstance(st.body[0],(ast.Raise,ast.Return)) and not st.orelse:
    env[st.test.left.id]=set();continue
   for n in ast.walk(st):
    if not isinstance(n,ast.Call):continue
    name=ast.unparse(n.func)
    if name in PROCESS and n.args:
     arg=code_arg(n.args[0])
     if arg is not None:emit(n,arg,env,'direct interpreter argv',True)
     elif isinstance(n.args[0],(ast.List,ast.Tuple)) and len(n.args[0].elts)==2:
      a=n.args[0].elts
      if isinstance(a[0],ast.Constant) and isinstance(a[1],ast.Constant) and (a[0].value,a[1].value)in [('python','-'),('python3','-'),('sh','-s'),('bash','-s')]:
       inp=next((k.value for k in n.keywords if k.arg=='input'),None)
       if inp is not None:emit(n,inp,env,'interpreter stdin program',True)
    if isinstance(n.func,ast.Name) and name in remote and name not in shadowed and n.args:
     arg=n.args[0]
     if isinstance(arg,ast.Call) and ast.unparse(arg.func)=='shlex.join' and arg.args:
      payload=code_arg(arg.args[0])
      if payload is not None:emit(n,payload,env,'SSH serialized nested interpreter code',True)
     elif isinstance(arg,ast.BinOp) and isinstance(arg.op,ast.Add) and isinstance(arg.left,ast.Constant) and isinstance(arg.left.value,str) and re.fullmatch(r'(?:sudo -n )?(?:sh|bash|python3?|node) -(?:c|lc|e) ',arg.left.value) and isinstance(arg.right,ast.Call) and ast.unparse(arg.right.func)=='shlex.quote' and arg.right.args:
      emit(n,arg.right.args[0],env,'SSH outer quote removed before interpreter code',True)
   if isinstance(st,ast.Assign):
    v=flow(st.value,env,True)
    for t in st.targets:
     if isinstance(t,ast.Name):env[t.id]=v
   if isinstance(st,(ast.If,ast.For,ast.While,ast.Try,ast.With)):
    for attr in ('body','orelse','finalbody'):
     if getattr(st,attr,None):walk(getattr(st,attr),dict(env))
 walk(tree.body,{})
 unique=lambda xs:list({(x['path'],x['line'],x['kind']):x for x in xs}.values())
 return {'findings':unique(findings),'calls':unique(calls)}
def self_test():
 positive=['import subprocess\nsubprocess.run(["sh","-c",input()])','import subprocess,sys\nx=sys.argv[1]\nsubprocess.run(["bash","-c",x])','import subprocess\nsubprocess.run(["python3","-c",input()])','import subprocess\nsubprocess.run(["node","-e",input()])','import shlex\nfrom controlled import remote\nremote(shlex.join(["bash","-c",input()]))','import shlex\nfrom controlled import remote\nremote("python3 -c "+shlex.quote(input()))','import subprocess\nsubprocess.run(["python3","-"],input=input())']
 negative=['import subprocess\nsubprocess.run(["sh","-c","date"])','import subprocess\nsubprocess.run(["python3","-c","import sys;print(sys.argv[1])",input()])','import subprocess\nx=input()\nif x not in ("date","uptime"):\n raise ValueError()\nsubprocess.run(["sh","-c",x])','import subprocess,shlex\nx=input()\nsubprocess.run(["sh","-c","printf %s "+shlex.quote(x)])','import subprocess,os\nsubprocess.run(["python3","-c",os.getenv("ADMIN_SCRIPT")])','from pathlib import Path\nimport subprocess\nsubprocess.run(["sh","-c",Path("operator-script").read_text()])','import shlex\nfrom controlled import remote\ncode="print(1)"\nremote("python3 -c "+shlex.quote(code))']
 for s in positive:assert inspect_source(s)['findings'],s
 for s in negative:assert not inspect_source(s)['findings'],s
 assert [inspect_source(s) for s in positive]==[inspect_source(s) for s in positive]
 return {'external_program_detected':len(positive),'safe_or_unproven_not_blocked':len(negative),'repeat_consistent':True,'executed_commands':0}
def analyze(files):
 tests=self_test();calls=[];blocking=[]
 for path,source in files.items():
  if path.endswith(('.py','.sh','.mjs')):
   r=inspect_source(source,path);calls+=r['calls'];blocking+=r['findings']
 return {'status':'failed'if blocking else'success','calls':calls,'blockingFindings':blocking,'tests':tests,'counts':{k:sum(x['classification']==k for x in calls)for k in ('fixed_trusted','dynamic_controlled','external_controllable','unknown')},'scope':'Direct interpreter argv/stdin and syntactically proven controlled.remote nested code. General wrappers, environment/file origin, embedded scripts and JavaScript/Shell inventory stay WARN; no interprocedural or exploit-completeness claim.'}
