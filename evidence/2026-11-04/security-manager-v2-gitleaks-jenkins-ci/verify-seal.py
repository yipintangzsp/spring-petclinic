from pathlib import Path
import json,hashlib
O=Path(__file__).resolve().parent;R=O.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
expected=json.loads((O/'evidence-sha256.json').read_text())
actual={str(p.relative_to(O)):sha(p) for p in O.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'}
assert actual==expected
code=json.loads((O/'code-sha256.json').read_text());assert all(sha(R/name)==h for name,h in code.items())
print(json.dumps({'newEvidenceSeal':'VERIFIED','evidenceFiles':len(actual),'newCodeAndDefinitionFiles':len(code),'jenkinsCI':'INCOMPLETE','CI_EXECUTION_READINESS':'CI_EXECUTION_NOT_READY','originalEvidenceIntegrity':'FAILED','canonicalRuntime':'14/16'}))
