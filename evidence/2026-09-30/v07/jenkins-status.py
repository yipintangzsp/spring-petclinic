"""Read Petclinic CI through the existing relay credentials without exposing them."""
import json
import shlex
import subprocess
import sys
from pathlib import Path

number = int(sys.argv[1])
code = r"""
const base = process.env.JENKINS_URL;
const auth = 'Basic ' + Buffer.from(process.env.JENKINS_USER + ':' + process.env.JENKINS_PASS).toString('base64');
const headers = {Authorization: auth};
(async () => {
  const build = '/job/petclinic-ci/NUMBER';
  const result = {};
  for (const [key, path] of [
    ['build', build + '/api/json?tree=number,result,building,duration,url'],
    ['stages', build + '/wfapi/describe']
  ]) {
    const response = await fetch(base + path, {headers});
    result[key] = response.ok ? await response.json() : {http_status: response.status};
  }
  const response = await fetch(base + build + '/consoleText', {headers});
  result.console = response.ok ? await response.text() : 'HTTP ' + response.status;
  console.log(JSON.stringify(result));
})().catch(error => {console.error(error.message); process.exit(1)});
""".replace("NUMBER", str(number))
remote = "sudo -n kubectl exec -n ns-devops deploy/github-webhook-relay -- node -e " + shlex.quote(code)
completed = subprocess.run(
    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o",
     "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "192.168.1.58", remote],
    capture_output=True, text=True, timeout=60, check=True,
)
result = json.loads(completed.stdout)
out = Path(__file__).resolve().parent
(out / f"jenkins-{number}.log").write_text(result.pop("console"))
(out / f"jenkins-{number}-status.json").write_text(json.dumps(result, indent=2))
print(json.dumps({
    "build": result["build"],
    "stages": [{"name": stage["name"], "status": stage["status"]}
               for stage in result.get("stages", {}).get("stages", [])],
}, indent=2))
print("\n".join((out / f"jenkins-{number}.log").read_text().splitlines()[-25:]))
