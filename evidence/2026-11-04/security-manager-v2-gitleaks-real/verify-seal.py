"""Read-only new-run seal verification. Does not repair historical integrity."""
from pathlib import Path
import hashlib,json
O=Path(__file__).resolve().parent;R=O.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((O/'evidence-sha256.json').read_text())
actual={str(p.relative_to(O)):sha(p) for p in O.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'}
assert actual==manifest,'new evidence added/removed/changed'
code=json.loads((O/'code-sha256.json').read_text())
assert all(sha(R/name)==h for name,h in code.items())
print(json.dumps({'newEvidenceSeal':'VERIFIED','files':len(actual),'codeFiles':len(code),'originalEvidenceIntegrity':'FAILED','canonicalRuntime':'14/16','release':0,'rollout':0}))
