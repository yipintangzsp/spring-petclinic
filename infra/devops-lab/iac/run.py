"""Run the approved, disposable Terraform/Ansible exercise with resource guards."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "infra" / "analytics"))
from controlled import HeavyRun, JENKINS_REQUEST, kube, remote, sample

NAMESPACE = "tf-devops-lab"
ADDRESSES = {"kubernetes_namespace_v1.lab", "kubernetes_resource_quota_v1.budget",
             "kubernetes_config_map_v1.environment"}


def gate(build, revision):
    route = f"/job/petclinic-ci/{build}/api/json?tree=building,result,actions[lastBuiltRevision[SHA1]]"
    args = ["sudo", "-n", "kubectl", "exec", "-i", "-n", "ns-devops",
            "deploy/github-webhook-relay", "--", "node", "--max-old-space-size=24", "-e", JENKINS_REQUEST]
    lock = Path.home() / ".codex" / "locks" / "petclinic-jenkins-relay.lock"
    with lock.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        response = json.loads(remote(shlex.join(args), json.dumps({"path": route, "method": "GET"}), timeout=40))
    value = json.loads(response["body"])
    if value["building"] or value["result"] != "SUCCESS":
        raise RuntimeError("Exact source must pass the full existing Jenkins release first")
    sources = [a["lastBuiltRevision"]["SHA1"] for a in value["actions"] if "lastBuiltRevision" in a]
    if revision not in sources:
        raise RuntimeError("Successful Jenkins source does not match requested revision")
    return value


EXECUTOR = r'''import json,subprocess,sys,time,pathlib,threading
p=json.load(sys.stdin);unit=p["unit"]
assert unit.startswith("petclinic-iac-") and all(c.isalnum() or c=="-" for c in unit)
a=["systemd-run","--quiet","--wait","--pipe","--collect","--unit="+unit,
 "-p","MemoryMax=768M","-p","CPUQuota=100%","-p","TasksMax=128",
 "-p","RuntimeMaxSec=600","-p","TimeoutStopSec=15",
 "-p","WorkingDirectory="+p["workdir"],"/usr/bin/env","TF_IN_AUTOMATION=1","TF_INPUT=0",
 "ANSIBLE_NOCOLOR=1","ANSIBLE_STDOUT_CALLBACK=ansible.posix.json",*p["args"]]
t=time.time();done=threading.Event();peak={"memoryPeakBytes":None,"cpuUsageUSec":None}
def observe():
 group=pathlib.Path("/sys/fs/cgroup/system.slice")/(unit+".service")
 while not done.wait(0.05):
  try:
   value=int((group/"memory.peak").read_text());peak["memoryPeakBytes"]=max(peak["memoryPeakBytes"] or 0,value)
   values=dict(line.split() for line in (group/"cpu.stat").read_text().splitlines());peak["cpuUsageUSec"]=int(values["usage_usec"])
  except (FileNotFoundError,ValueError,KeyError):pass
watcher=threading.Thread(target=observe,daemon=True);watcher.start()
try:
 r=subprocess.run(a,capture_output=True,text=True,timeout=620)
 stats=subprocess.run(["systemctl","show",unit,"-p","MemoryPeak","-p","CPUUsageNSec","-p","TasksCurrent"],capture_output=True,text=True,timeout=10)
 result={"exit":r.returncode,"stdout":r.stdout,"stderr":r.stderr,"elapsed_seconds":time.time()-t,"systemd":stats.stdout,"cgroup_peak":peak}
finally:
 done.set();watcher.join(timeout=2)
 subprocess.run(["systemctl","stop",unit],capture_output=True,timeout=20)
 subprocess.run(["systemctl","reset-failed",unit],capture_output=True,timeout=10)
 check=subprocess.run(["systemctl","show",unit,"-p","MainPID","-p","TasksCurrent","-p","ActiveState"],capture_output=True,text=True,timeout=10)
 if "result" in locals():
  result["stop_state"]=check.stdout
  result["stopped"]="MainPID=0" in check.stdout and "ActiveState=inactive" in check.stdout
  print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=int, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("An exact approved source SHA is required")
    approved = subprocess.check_output(["git", "show", args.revision + ":infra/devops-lab/iac/run.py"], cwd=ROOT)
    if approved != Path(__file__).read_bytes():
        raise RuntimeError("Run the controller from the approved source without local edits")
    evidence = args.evidence
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    def save(name, value):
        (evidence / name).write_text(value if isinstance(value, str) else json.dumps(value, indent=2))
    save("jenkins-gate.json", gate(args.build, args.revision))
    if kube(["get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "json"]):
        raise RuntimeError("Existing namespace preserved; choose recovery, never adopt or delete blindly")
    prefix = "infra/devops-lab/iac/"
    names = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", args.revision, "--", prefix], cwd=ROOT, text=True).splitlines()
    files = {name[len(prefix):]: subprocess.check_output(["git", "show", args.revision + ":" + name], cwd=ROOT, text=True) for name in names}
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
    work = "/opt/petclinic-observability/labs/iac-" + stamp
    installer = r'''import json,pathlib,sys,os
x=json.load(sys.stdin);w=pathlib.Path(x["work"]);w.mkdir(parents=True,mode=0o700,exist_ok=False)
s=w/"source";s.mkdir(mode=0o700)
for name,text in x["files"].items():
 p=pathlib.PurePosixPath(name);assert not p.is_absolute() and ".." not in p.parts
 f=s/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text);os.chmod(f,0o600)
for n in ["main.tf",".terraform.lock.hcl"]:
 f=w/n;f.write_text((s/"terraform"/n).read_text());os.chmod(f,0o600)
print(str(w))'''
    remote("sudo -n python3 -c " + shlex.quote(installer), json.dumps({"work": work, "files": files}))
    save("runtime.json", {"revision": args.revision, "build": args.build, "workdir": work,
        "namespace": NAMESPACE, "limit": {"memory": "768M", "cpu": "100%", "tasks": 128, "runtime_seconds": 600}})
    guard = None
    def command(name, argv, expected=(0,)):
        if guard:
            guard.check()
        print("STEP", name, flush=True)
        save("current-step.json", {"name": name, "started": time.time()})
        unit = "petclinic-iac-" + stamp.lower() + "-" + name
        if guard:
            guard.compute_stopped = False
        r = json.loads(remote("sudo -n python3 -c " + shlex.quote(EXECUTOR),
            json.dumps({"unit": unit, "workdir": work, "args": argv}), timeout=660))
        save(name + ".json", r)
        if not r.get("stopped"):
            raise RuntimeError("Owned transient process stop could not be confirmed")
        if guard:
            guard.compute_stopped = True
        if r["exit"] not in expected:
            raise RuntimeError(name + " failed; private output retained in " + str(evidence))
        if guard:
            guard.check()
        return r
    def tf(name, params, expected=(0,)):
        return command(name, ["terraform", *params], expected)
    def plan(name, destroy=False, expected=2):
        tf(name, ["plan", "-no-color", "-input=false", "-parallelism=1", "-lock-timeout=10s",
            "-detailed-exitcode", "-out=" + name + ".tfplan", *(["-destroy"] if destroy else [])], (expected,))
        return json.loads(tf(name + "-show", ["show", "-json", name + ".tfplan"])["stdout"])
    def changed(value):
        return {r["address"]: r["change"]["actions"] for r in value.get("resource_changes", []) if r["change"]["actions"] != ["no-op"]}
    def apply(name):
        return tf(name + "-apply", ["apply", "-no-color", "-input=false", "-parallelism=1", name + ".tfplan"])
    def ansible(name, extra=None, preview=False, expected=(0,)):
        cmd = ["ansible-playbook", "-i", work + "/source/ansible/inventory.ini", work + "/source/ansible/configure.yaml",
               "-e", json.dumps({"iac_workdir": work, **(extra or {})})]
        if preview:
            cmd += ["--check", "--diff"]
        result = command(name, cmd, expected)
        value = json.loads(result["stdout"])
        save(name + "-stats.json", value["stats"])
        return value["stats"]["localhost"]
    def digest():
        return remote(shlex.join(["sudo", "-n", "sha256sum", work + "/environment.auto.tfvars.json"])).split()[0]
    owned_uid = None
    def verify_owned(phase):
        n = kube(["get", "ns", NAMESPACE, "-o", "json"])
        if n["metadata"]["uid"] != owned_uid or n["metadata"]["labels"].get("petclinic.devops.local/owner") != "terraform-iac-lab":
            raise RuntimeError("Namespace ownership changed; preserve all resources")
        objects = kube(["-n", NAMESPACE, "get", "all,serviceaccounts,configmaps,secrets,pvc,resourcequota,limitrange,roles,rolebindings,networkpolicy,ingress,certificates,issuers", "-o", "json"])["items"]
        allowed = {("ServiceAccount", "default"), ("ConfigMap", "kube-root-ca.crt"), ("ConfigMap", "environment-manifest"), ("ResourceQuota", "lab-budget")}
        if any((x["kind"], x["metadata"]["name"]) not in allowed for x in objects):
            raise RuntimeError("Foreign or persistent resources found; refusing namespace removal")
        states = tf(phase + "-state-list", ["state", "list"])["stdout"].splitlines()
        if set(states) != ADDRESSES:
            raise RuntimeError("Unexpected Terraform state; preserve it")
        save(phase + "-owned-resources.json", objects)
    before = []
    for _ in range(3):
        before.append(sample())
        time.sleep(2)
    save("admission-samples.json", before)
    with HeavyRun("terraform-ansible-lab", 1024, evidence) as guard:
        try:
            tf("versions", ["version", "-json"])
            preview = ansible("ansible-preview", preview=True)
            if preview["changed"] != 1:
                raise RuntimeError("Check mode must predict one file change")
            exists = remote(shlex.join(["sudo", "-n", "test", "!", "-e", work + "/environment.auto.tfvars.json"]) + " && echo absent").strip()
            if exists != "absent":
                raise RuntimeError("Check mode unexpectedly changed the destination")
            first = ansible("ansible-first")
            second = ansible("ansible-second")
            if first["changed"] != 1 or second["changed"] != 0:
                raise RuntimeError("Ansible configuration is not idempotent")
            original = digest()
            invalid = ansible("ansible-invalid", {"iac_namespace_name": "petclinic"}, expected=(2,))
            if invalid["failures"] != 1 or digest() != original:
                raise RuntimeError("Invalid inputs must fail without modifying the config")
            tf("init", ["init", "-no-color", "-input=false", "-lockfile=readonly"])
            tf("validate", ["validate", "-no-color"])
            initial = plan("create")
            if changed(initial) != {a: ["create"] for a in ADDRESSES}:
                raise RuntimeError("Initial plan must create only the three isolated resources")
            apply("create")
            owned_uid = tf("namespace-uid", ["output", "-raw", "namespace_uid"])["stdout"].strip()
            if changed(plan("repeat", expected=0)):
                raise RuntimeError("Repeated plan must have no changes")
            verify_owned("before-drift")
            cm = kube(["-n", NAMESPACE, "get", "cm", "environment-manifest", "-o", "json"])
            kube(["-n", NAMESPACE, "patch", "cm", "environment-manifest", "--type=json", "-p", json.dumps([
                {"op": "test", "path": "/metadata/uid", "value": cm["metadata"]["uid"]},
                {"op": "replace", "path": "/data/config_revision", "value": "out-of-band"}])])
            drift = plan("drift")
            if changed(drift) != {"kubernetes_config_map_v1.environment": ["update"]}:
                raise RuntimeError("Drift plan must repair only the owned ConfigMap")
            apply("drift")
            restored = kube(["-n", NAMESPACE, "get", "cm", "environment-manifest", "-o", "json"])
            if restored["data"]["config_revision"] != "v1" or restored["metadata"]["uid"] != cm["metadata"]["uid"]:
                raise RuntimeError("ConfigMap must be repaired in place")
            if changed(plan("after-repair", expected=0)):
                raise RuntimeError("Plan after repair must have no changes")
            verify_owned("before-destroy")
            ending = plan("destroy", destroy=True)
            if changed(ending) != {a: ["delete"] for a in ADDRESSES}:
                raise RuntimeError("Destroy plan contains unexpected resources")
            apply("destroy")
            if kube(["get", "ns", NAMESPACE, "--ignore-not-found", "-o", "json"]):
                raise RuntimeError("Owned namespace was not removed")
            if tf("final-state", ["state", "list"])["stdout"].strip():
                raise RuntimeError("Final state must be empty")
            if changed(plan("final-destroy", destroy=True, expected=0)):
                raise RuntimeError("Repeated destroy plan must have no changes")
            save("after.json", sample())
            save("acceptance.json", {"status": "success", "source": args.revision, "jenkins_build": args.build,
                "namespace_uid": owned_uid, "namespace_removed": True, "managed_objects": 3,
                "ansible_preview_did_not_write": True, "ansible_second_changed": 0,
                "invalid_input_rejected_without_write": True, "terraform_repeat_exit": 0,
                "drift_exit": 2, "drift_repaired_in_place": True, "after_repair_exit": 0,
                "final_destroy_exit": 0, "state_preserved_at": work, "new_pods_or_pvcs": 0,
                "completed_utc": dt.datetime.now(dt.timezone.utc).isoformat()})
        except BaseException as error:
            save("error.json", {"error": str(error), "namespace_uid": owned_uid,
                "state_preserved_at": work, "cleanup": "Metadata retained for scoped recovery; never force destroy after an ownership or safety failure"})
            raise
    from controlled import jenkins
    save("jenkins-restored.json", jenkins("/api/json?tree=quietingDown,jobs[name,lastBuild[building]]"))
    print("IAC_LIFECYCLE_ACCEPTANCE=SUCCESS", flush=True)


if __name__ == "__main__":
    main()
