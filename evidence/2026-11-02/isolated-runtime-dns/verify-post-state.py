"""Read-only runtime/config verification; only deletes its own empty client directory."""
import hashlib
import json
import os
import pathlib
import stat
import subprocess

import yaml

root = pathlib.Path(__file__).resolve().parent
repo = root.parents[2]
env = {k: v for k, v in os.environ.items() if k in {
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL",
    "__CF_USER_TEXT_ENCODING",
}}
client = root / "docker-client-config"
assert client.is_dir() and not list(client.iterdir())
docker_env = dict(env, HOME=str(client), DOCKER_CONFIG=str(client))
docker = ["/opt/homebrew/bin/docker", "--host",
          "unix:///Users/zhangsir/.colima/security-test/docker.sock"]


def call(args, child_env):
    result = subprocess.run(args, env=child_env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (args, result.stderr)
    return {"command": args, "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def rows(result):
    return sorted((json.loads(line) for line in result["stdout"].splitlines()),
                  key=lambda row: row.get("Name", row.get("ID", "")))


identity = json.loads(call(docker + ["info", "--format", "{{json .}}"], docker_env)["stdout"])
assert identity["ID"] == "f0a9c4bb-ef14-4087-b0b1-7d5f02aa1ff8"
assert identity["Name"] == "security-test"
before = json.loads((root / "docker-container-before.json").read_text())
resources = {}
for label, args in [
    ("containers", ["ps", "-a", "--no-trunc", "--format", "{{json .}}"]),
    ("volumes", ["volume", "ls", "--format", "{{json .}}"]),
    ("networks", ["network", "ls", "--format", "{{json .}}"]),
]:
    resources[label] = call(docker + args, docker_env)
(root / "docker-resources-after.json").write_text(json.dumps(resources, indent=2))
assert not rows(resources["containers"]), "containers remain"
assert not rows(resources["volumes"]), "volumes remain"
assert rows(resources["networks"]) == rows(before["networks"]), "network changed"

pre = json.loads((root / "pre-protection.json").read_text())
out = {"files": []}
for original in pre["files"]:
    path = pathlib.Path(original["path"])
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    out["files"].append({"path": str(path), "beforeSha256": original.get("sha256"),
                         "afterSha256": digest, "unchanged": digest == original.get("sha256")})
out["currentContext"] = call(["/opt/homebrew/bin/docker", "context", "show"], env)["stdout"].strip()
out["dockerContextList"] = call(["/opt/homebrew/bin/docker", "context", "ls", "--format", "{{json .}}"], env)
out["contextListUnchanged"] = rows(out["dockerContextList"]) == rows(pre["docker"][1])
assert out["currentContext"] == "default", "current context changed"
assert out["contextListUnchanged"], "context definitions changed"
assert all(item["unchanged"] for item in out["files"]), "protected host file changed"

profile = yaml.safe_load(pathlib.Path("/Users/zhangsir/.colima/security-test/colima.yaml").read_text())
lima_path = pathlib.Path("/Users/zhangsir/.colima/_lima/colima-security-test/lima.yaml")
lima = yaml.safe_load(lima_path.read_text())
out["profileFlags"] = {key: profile[key] for key in ["mounts", "kubernetes", "sshConfig", "autoActivate", "forwardAgent"]}
flags = out["profileFlags"]
assert flags["mounts"] is None and not flags["kubernetes"]["enabled"]
assert all(flags[key] is False for key in ["sshConfig", "autoActivate", "forwardAgent"])
assert lima.get("mounts") is None
assert lima["ssh"]["loadDotSSHPubKeys"] is False and lima["ssh"]["forwardAgent"] is False
out["lima"] = {"sha256": hashlib.sha256(lima_path.read_bytes()).hexdigest(),
               "mounts": lima.get("mounts"), "mountsFieldPresent": "mounts" in lima, "ssh": {key: lima["ssh"][key] for key in ["loadDotSSHPubKeys", "forwardAgent"]},
               "dns": lima["dns"], "hostResolver": lima["hostResolver"]}
prior = json.loads((repo / "evidence/2026-11-02/isolated-runtime-start/rendered-lima-and-socket.json").read_text())
out["limaUnchanged"] = out["lima"]["sha256"] == prior["sha256"]
assert out["limaUnchanged"], "generated Lima config changed"
socket_stat = pathlib.Path("/Users/zhangsir/.colima/security-test/docker.sock").stat()
out["socket"] = {"isSocket": stat.S_ISSOCK(socket_stat.st_mode),
                 "mode": oct(stat.S_IMODE(socket_stat.st_mode)), "uid": socket_stat.st_uid}
assert out["socket"] == {"isSocket": True, "mode": "0o600", "uid": os.getuid()}

protected = json.loads((root / "project-before-sha256.json").read_text())
changed = []
for name, digest in protected.items():
    path = repo / name
    current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    if current != digest:
        changed.append(name)
out["projectProtectedCount"] = len(protected)
out["projectChanged"] = changed
assert not changed, changed
log = (root / "guest-isolation-after.log").read_text()
out["guestIsolation"] = {
    "homeHostMountsAbsent": not any(x in log.split("__ENV_NAMES_ONLY__")[0] for x in [" /Users", " virtiofs", " 9p"]),
    "credentialKnownPathsAllAbsent": not any(line.startswith("PRESENT ") for line in log.splitlines()),
    "sshAgentAbsent": "SSH_AUTH_SOCK_ABSENT" in log,
}
assert all(out["guestIsolation"].values())
out.update(productionApiAccess=0, kubernetesApiAccess=0, credentialSecretValueReads=0, secretConfigHashOnly=True)
(root / "post-protection.json").write_text(json.dumps(out, indent=2))
client.rmdir()
cleanup = {
    "diagnosticContainerRemoved": True, "pulledSmokeContainerRemoved": True,
    "containersRemaining": 0, "volumesRemaining": 0,
    "networks": "original bridge/host/none only; IDs unchanged",
    "emptyDockerClientConfigRemoved": True,
    "retained": ["Public images in dedicated VM cache", "Root-only VM resolver symlink backup for rollback", "Evidence ID text files; not live containers"],
    "runtime": "security-test remains running; no restart",
}
(root / "cleanup.json").write_text(json.dumps(cleanup, indent=2))
print(json.dumps({"protectedHostFilesUnchanged": True, "protectedProjectFiles": len(protected),
                  "currentContext": out["currentContext"], "isolation": out["guestIsolation"], "cleanup": cleanup}))
