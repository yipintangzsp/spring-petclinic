"""Create exact candidate integrity metadata. Never updates active V1 locks."""
import hashlib
import json
import pathlib

root = pathlib.Path(__file__).resolve().parents[3]
base = root / "evidence/2026-11-02/summary-v2-migration"
v1 = json.loads((base / "V1_IDENTITY.json").read_text())
target = root / "infra/security/summary-v2/candidate-integrity.json"
if target.exists():
    raise SystemExit("Refusing to overwrite candidate identity; use a new reviewed revision")
sha = lambda b: hashlib.sha256(b).hexdigest()
files = {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted((root / "infra/security/summary-v2").glob("*.mjs")) if not p.name.endswith(".test.mjs") and p.name != "fixture-harness.mjs"}
files.update({p: x["sha256"] for p, x in v1["files"].items() if p.startswith("infra/security/policy/")})
producer = "infra/security/summary-v2/producer.mjs"
identity = {"identity": "SummaryProducerV2-candidate-" + files[producer], "sha256": files[producer]}
contract = {"schema": 1, "activation": "CANDIDATE_ONLY_NOT_IN_PRODUCTION", "selection": "explicit trusted version; no fallback", "versions": {
    "V1": {"producer": {"identity": v1["identity"], "sha256": v1["producerSha256"]}, "consumers": ["V1", "V2-explicit-rollback"], "files": {p: x["sha256"] for p, x in v1["files"].items()}},
    "V2": {"producer": identity, "consumers": ["SummaryConsumerV2", "PromotionConsumerV2", "RegressionConsumerV2"], "files": files},
}}
target.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
(base / "V2_CANDIDATE_IDENTITY.json").write_text(json.dumps({"producer": identity, "contractSha256": sha(target.read_bytes()), "activation": contract["activation"]}, indent=2) + "\n")
print(json.dumps({"identity": identity, "files": len(files), "activeV1ContractChanged": False}))
