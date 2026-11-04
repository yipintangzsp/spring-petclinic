from pathlib import Path
import json,runpy
p=Path(__file__).resolve().parent;api=runpy.run_path(str(p/'inspect-production.py'));root=json.loads((p/'tool-preparation.json').read_text())['workspace']
s=r'''
import json,pathlib
p=pathlib.Path(ROOT)/'outputs/attempt2-case5-semgrep-error/semgrep.raw.json';r=json.loads(p.read_text());print(json.dumps({'classification':'REAL_READ_ONLY_NATIVE_PARSER_OBSERVATION','rawDigest':__import__('hashlib').sha256(p.read_bytes()).hexdigest(),'native':r['reports'],'note':'Original failed expectation retained; native tool output is authoritative'}))
'''
x=json.loads(api['remote']('sudo -n python3 -','ROOT='+repr(root)+'\n'+s));api['save']('attempt2-parser-observation.json',x);print(json.dumps(x))
