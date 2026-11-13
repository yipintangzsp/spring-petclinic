"""Freeze the current working-tree V1 before staging a Summary migration.

No credentials, runtime workspace, git internals, or decrypted material are read.
Existing encrypted repository files are copied verbatim for source-hash checks.
The destination is create-only. This is not an activation/rollback command.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[3]
destination = root / sys.argv[1]
if destination.exists():
    raise SystemExit("Refusing to overwrite an existing V1 identity")
snapshot = destination / "v1-tree"
snapshot.mkdir(parents=True)
sha = lambda b: hashlib.sha256(b).hexdigest()
write = lambda p, v: p.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")

before = {}
for parent in ("infra", "resources", "vars", "docs", "evidence", "k8s"):
    for path in (root / parent).rglob("*"):
        if path.is_file() and destination not in path.parents and not path.is_symlink():
            before[str(path.relative_to(root))] = sha(path.read_bytes())
for path in root.glob("Jenkinsfile*"):
    if path.is_file():
        before[str(path.relative_to(root))] = sha(path.read_bytes())
write(destination / "before-sha256.json", before)

selected = set()
for parent in ("infra", "resources", "vars", "k8s"):
    selected.update(p for p in (root / parent).rglob("*") if p.is_file() and not p.is_symlink())
selected.update(p for p in root.glob("Jenkinsfile*") if p.is_file())
for name in ("pom.xml", "mvnw", "evidence/2026-11-01/policy-engine/gate-decision-before.json"):
    if (root / name).is_file():
        selected.add(root / name)
files = {}
for path in sorted(selected):
    relative = path.relative_to(root)
    target = snapshot / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)
    files[str(relative)] = {"sha256": sha(path.read_bytes()), "mode": path.stat().st_mode & 0o777}
tree_digest = sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())
producer = "infra/security/security-summary.mjs"
identity = {
    "identity": "SummaryProducerV1-" + files[producer]["sha256"],
    "producer": producer,
    "producerSha256": files[producer]["sha256"],
    "schema": 1,
    "snapshotTreeSha256": tree_digest,
    "files": files,
    "gitHead": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "gitBranch": subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip(),
    "identityBasis": "working-tree bytes including untracked Policy implementation; not HEAD alone",
    "activation": "V1 remains active. Snapshot is a create-only rollback target, not an auto-allowlist.",
}
write(destination / "V1_IDENTITY.json", identity)
print(json.dumps({"identity": identity["identity"], "files": len(files), "beforeFiles": len(before), "treeSha256": tree_digest}))
