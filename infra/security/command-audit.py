"""Conservative static inventory; never executes inspected scripts or shell commands."""
import ast,json,pathlib,re,subprocess

def classify(node):
 name=ast.unparse(node.func)
 if not (name.startswith('subprocess.') or name in ('os.system','os.popen','eval','exec')):return None
 shell=any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords)
 arg=node.args[0] if node.args else None
 literal=lambda x:isinstance(x,ast.Constant) and isinstance(x.value,(str,int,float))
 external=any(isinstance(x,ast.Call) and (ast.unparse(x.func) in ('input','os.getenv','os.environ.get') or ast.unparse(x.func).endswith('.getParameter')) for x in ast.walk(arg)) if arg else False
 if external and (shell or name in ('os.system','os.popen','eval','exec')):return {'classification':'dangerous','reason':'direct external input reaches interpreter or shell','sink':name}
 fixed=arg is not None and (literal(arg) or isinstance(arg,(ast.List,ast.Tuple)) and all(literal(x) for x in arg.elts))
 if fixed and name not in ('eval','exec'):return {'classification':'safe','reason':'fixed command and literal arguments; scoped to this call only','sink':name}
 return {'classification':'unknown','reason':'dynamic arguments, environment, wrapper or remote-shell trust needs manual review; argument-list calls are not proof of injection','sink':name}

def analyze(files):
 items=[];errors=[]
 for f,source in files.items():
  suffix=pathlib.PurePosixPath(f).suffix
  if suffix=='.py':
   try: tree=ast.parse(source)
   except (SyntaxError,UnicodeError) as e:errors.append({'path':f,'error':type(e).__name__});continue
   for node in ast.walk(tree):
    if isinstance(node,ast.Call):
     value=classify(node)
     if value:items.append({'path':f,'line':node.lineno,**value})
  elif suffix=='.sh':
   for i,line in enumerate(source.splitlines(),1):
    if re.search(r'\b(eval|exec|bash|sh|python3?)\b|\$\(',line) and not line.lstrip().startswith('#'):items.append({'path':f,'line':i,'classification':'unknown','reason':'shell expansion inventory; no data-flow proof'})
 return {'status':'failed' if errors else 'success','scope':'tracked Python/Shell; conservative local AST, no interprocedural or remote exploit proof','items':items,'errors':errors,'counts':{k:sum(x['classification']==k for x in items) for k in ('safe','dangerous','unknown')},'policy':'script candidates WARN pending manual trust-boundary review'}

def main():
 names=subprocess.check_output(['git','ls-files','src/main','infra'],text=True).splitlines()
 result=analyze({f:pathlib.Path(f).read_text() for f in names if pathlib.Path(f).suffix in ('.py','.sh')})
 pathlib.Path('.devsecops').mkdir(exist_ok=True);pathlib.Path('.devsecops/command-audit.json').write_text(json.dumps(result,indent=2));print(json.dumps(result['counts']))
 if result['errors']:raise SystemExit(1)
if __name__=='__main__':main()
