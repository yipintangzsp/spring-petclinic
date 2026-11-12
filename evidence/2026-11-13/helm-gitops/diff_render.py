#!/usr/bin/env python3
"""Structured diff: helm rendered (JSON docs) vs (a) baseline fixture current-desired.json,
(b) local k8s/production plain manifests. Output: human txt + json summary."""
import json, sys, glob
import yaml

def key(doc):
    md = doc.get("metadata") or {}
    return (doc.get("apiVersion"), doc.get("kind"), md.get("namespace"), md.get("name"))

def load_rendered(path):
    docs = {}
    with open(path) as f:
        for doc in yaml.safe_load_all(f):
            if doc is None:
                continue
            docs[key(doc)] = doc
    return docs

def load_baseline(path):
    with open(path) as f:
        arr = json.load(f)
    return {key(d): d for d in arr}

def load_production(pattern):
    docs = {}
    extras = []
    for path in sorted(glob.glob(pattern)):
        if "/._" in path or path.split("/")[-1].startswith("._"): continue
        with open(path) as f:
            for doc in yaml.safe_load_all(f):
                if doc is None:
                    continue
                if isinstance(doc, dict) and "kind" in doc:
                    docs[key(doc)] = doc
                else:
                    extras.append(path)
    return docs, extras

def deep_diff(a, b, path=""):
    diffs = []
    if type(a) != type(b):
        # int vs str etc.
        diffs.append({"path": path, "rendered": a, "other": b})
        return diffs
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a:
                diffs.append({"path": p, "rendered": "<absent>", "other": b[k]})
            elif k not in b:
                diffs.append({"path": p, "rendered": a[k], "other": "<absent>"})
            else:
                diffs.extend(deep_diff(a[k], b[k], p))
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append({"path": path, "rendered_len": len(a), "other_len": len(b),
                          "rendered": a, "other": b})
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                diffs.extend(deep_diff(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            diffs.append({"path": path, "rendered": a, "other": b})
    return diffs

def compare(name, rendered, other):
    out = {"comparison": name, "rendered_count": len(rendered), "other_count": len(other),
           "only_in_rendered": [], "only_in_other": [], "per_resource": {}}
    for k in sorted(set(rendered) | set(other), key=lambda x: str(x)):
        ks = "/".join(str(x) for x in k)
        if k not in other:
            out["only_in_rendered"].append(ks)
        elif k not in rendered:
            out["only_in_other"].append(ks)
        else:
            d = deep_diff(rendered[k], other[k])
            out["per_resource"][ks] = {"diff_count": len(d), "diffs": d}
    out["total_field_diffs"] = sum(v["diff_count"] for v in out["per_resource"].values())
    return out

def main():
    rendered = load_rendered("/tmp/helm-evidence/rendered-prod.yaml")
    baseline = load_baseline("/tmp/helm-evidence/prodtree/infra/helm/baseline/current-desired.json")
    prod, extras = load_production("/tmp/helm-evidence/prodtree/k8s/production/*.yaml")
    results = [compare("rendered_vs_baseline_fixture_340ef4b8", rendered, baseline),
               compare("rendered_vs_local_k8s_production", rendered, prod)]
    with open("/tmp/helm-evidence/render-diff.json", "w") as f:
        json.dump({"comparisons": results, "production_non_k8s_or_extra": extras}, f, indent=2, ensure_ascii=False)
    for r in results:
        print(f"== {r['comparison']}: rendered={r['rendered_count']} other={r['other_count']} field_diffs={r['total_field_diffs']}")
        print(f"   only_in_rendered: {r['only_in_rendered']}")
        print(f"   only_in_other: {r['only_in_other']}")
        for ks, v in r["per_resource"].items():
            if v["diff_count"]:
                print(f"   DIFF {ks}: {v['diff_count']}")
                for d in v["diffs"][:30]:
                    print(f"      {json.dumps(d, ensure_ascii=False)[:400]}")

if __name__ == "__main__":
    main()
