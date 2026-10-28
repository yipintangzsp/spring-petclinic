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

def main():
 files=subprocess.check_output(['git','ls-files','src/main','infra'],text=True).splitlines();items=[];errors=[]
 for f in files:
  p=pathlib.Path(f)
  if p.suffix=='.py':
   try: tree=ast.parse(p.read_text())
   except (SyntaxError,UnicodeError) as e:errors.append({'path':f,'error':type(e).__name__});continue
   for node in ast.walk(tree):
    if isinstance(node,ast.Call):
     value=classify(node)
     if value:items.append({'path':f,'line':node.lineno,**value})
  elif p.suffix=='.sh':
   for i,line in enumerate(p.read_text().splitlines(),1):
    if re.search(r'\b(eval|exec|bash|sh|python3?)\b|\$\(',line) and not line.lstrip().startswith('#'):items.append({'path':f,'line':i,'classification':'unknown','reason':'shell execution/expansion inventory; no shell data-flow proof'})
 result={'status':'success' if not errors else 'failed','scope':'tracked Python and Shell scripts; conservative local AST/inventory, no interprocedural or remote-shell exploit proof','items':items,'errors':errors,'counts':{k:sum(x['classification']==k for x in items) for k in ('safe','dangerous','unknown')},'policy':'all script candidates remain WARN until reviewed and Semgrep positive/negative validation; no script rule promoted in this round'}
 pathlib.Path('.devsecops').mkdir(exist_ok=True);pathlib.Path('.devsecops/command-audit.json').write_text(json.dumps(result,indent=2));print(json.dumps(result['counts']))
 if errors:raise SystemExit('Command inventory parse errors; inspect report')
if __name__=='__main__':main()
