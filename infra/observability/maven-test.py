#!/usr/bin/env python3
"""Run integration tests and reclaim only newly created, stopped test containers."""
import json
import pathlib
import subprocess
import sys
import time


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


before_containers = set(docker("ps", "-aq", "--no-trunc").split())
before_volumes = set(docker("volume", "ls", "-q").split())
started = time.time()
result = subprocess.run(["nice", "-n", "10", "./mvnw", "-B", "clean", "test"])
report = {"test_exit_code": result.returncode, "removed": [], "retained": []}
try:
    ids = docker("ps", "-aq", "--no-trunc").split()
    for ident in ids:
        if ident in before_containers:
            continue
        c = json.loads(docker("inspect", ident))[0]
        labels = c.get("Config", {}).get("Labels") or {}
        if (labels.get("com.docker.compose.project") != "petclinic-ci"
                or labels.get("com.docker.compose.service") != "postgres"):
            continue
        volumes = [m["Name"] for m in c.get("Mounts", []) if m.get("Type") == "volume"]
        # Never remove a pre-existing volume, a live container, or another workspace's test.
        same_workspace = pathlib.Path(labels.get("com.docker.compose.project.working_dir", "/")).resolve() == pathlib.Path.cwd().resolve()
        if c["State"]["Running"] or not same_workspace or any(v in before_volumes for v in volumes):
            report["retained"].append({"id": ident, "reason": "ownership, lifecycle or pre-existing-volume guard"})
            continue
        docker("rm", "--volumes", ident)
        report["removed"].append({"id": ident, "anonymous_volumes": volumes})
finally:
    report["elapsed_seconds"] = round(time.time() - started, 2)
    dest = pathlib.Path("target/platform")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "integration-test-cleanup.json").write_text(json.dumps(report, indent=2))
sys.exit(result.returncode)
