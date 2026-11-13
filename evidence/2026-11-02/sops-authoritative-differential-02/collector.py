"""Collector never translates Gate exit codes; preserves bounded actual subprocess metadata."""
from pathlib import Path
import sys,os,json
sys.path.insert(0,'/fixture/python')
from sops_observation import observe_child
record=observe_child(['/fixture/node/bin/node','--import','/fixture/observer.mjs','/fixture/work/infra/security/secrets-gate.mjs'],env=dict(os.environ),cwd='/fixture/work',identity='system:serviceaccount:devsecops-system:security-fixture-executor',evidence_ref='result.json',timeout=160,max_output=2*1024*1024)
Path('/fixture/results/child.json').write_text(json.dumps(record))
