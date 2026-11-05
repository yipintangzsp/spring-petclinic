"""One bounded operator session. Scan only after the exact Jenkins build is waiting."""
import hashlib, json, re, runpy, shlex, subprocess, sys, tempfile, time, os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, ProxyHandler, build_opener
from xml.etree import ElementTree as XML

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
JOB = 'security-gitleaks-demo'
ITEM = '/job/' + JOB
JENKINS = 'http://jenkins.devops.local'
VIEW = 'http://security.devops.local:17862'
FORM = 'application/x-www-form-urlencoded'
PROD = runpy.run_path(str(OUT.parent / 'security-manager-v2-loki/inspect-production.py'))
sys.path.insert(0, '/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE
RELAY = 'sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e ' + shlex.quote(
    NODE.replace("method:input.method||'GET',headers", "method:input.method||'GET',redirect:'manual',headers"))
SIGNER = r'''
import {createPrivateKey,createPublicKey,generateKeyPairSync,sign} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {createInterface} from 'node:readline';
const [file,mode]=process.argv.slice(1);
if(mode==='new') writeFileSync(file, generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'}),{flag:'wx',mode:0o600});
const privateKey=createPrivateKey(readFileSync(file));
const publicKey=createPublicKey(privateKey);
console.log(publicKey.export({format:'der',type:'spki'}).toString('base64'));
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
  const payload=Buffer.from(line);
  console.log(payload.toString('base64url')+'.'+sign(null,payload,privateKey).toString('base64url'));
}
'''
FIELDS = ('runId pluginId scenarioId evidenceClass state scannerExecuted scannerExitCode findingsCount '
          'executionHost executionIdentity toolVersion toolSha256 policyDecision evaluationCount '
          'resultDigest rawReportDigest factDigest scannerStartedAt scannerCompletedAt').split()


def expect(condition, why):
    if not condition:
        raise RuntimeError(why)


def save(name, value):
    with (OUT / name).open('x') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write('\n')


def jenkins(path, method='GET', body=None, kind=None, statuses=(200,)):
    expect(path.startswith(ITEM + '/') or path in {
        ITEM, '/pipeline-model-converter/validate', '/createItem?name=' + JOB
    } or re.fullmatch(r'/queue/item/[0-9]+/api/json', path), 'Endpoint outside demo scope')
    data = {'path': path, 'method': method, 'timeout': 12000}
    if body is not None:
        data.update(body=body, type=kind)
    r = json.loads(PROD['remote'](RELAY, json.dumps(data), 22))
    expect(r['status'] in statuses, f'{method} {path} returned HTTP {r["status"]}')
    return r


def jjson(path):
    return json.loads(jenkins(path)['body'])


def view(path, data=None, token=None):
    body = None if data is None else json.dumps(data).encode()
    headers = {} if token is None else {'Origin': VIEW, 'X-CSRF-Token': token, 'Content-Type': 'application/json'}
    try:
        with build_opener(ProxyHandler({})).open(Request(VIEW + path, body, headers), timeout=5) as response:
            expect(response.status == (200 if data is None else 202), 'Unexpected Security Manager HTTP status')
            return json.load(response)
    except HTTPError as e:
        raise RuntimeError(f'Security Manager {path} returned HTTP {e.code}') from None


def wait(probe, label, seconds, interval=2):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = probe()
        if value is not None:
            return value
        time.sleep(interval)
    raise RuntimeError('Timed out waiting for ' + label)


def run(scenario, signer, number=None):
    finding = scenario == 'Finding'
    expected = 'FAILURE' if finding else 'SUCCESS'
    decision = 'FAIL' if finding else 'PASS'
    fixture = 'controlled-finding' if finding else 'clean'
    if number is None:
        r = jenkins(ITEM + '/buildWithParameters', 'POST', urlencode({'SCENARIO': scenario}), FORM, (201,))
        location = urlsplit(r['location'] or '').path
        expect(re.fullmatch(r'/queue/item/[0-9]+/', location), 'Build did not return an exact queue link')
        def executable():
            q = jjson(location + 'api/json')
            expect(not q.get('cancelled'), 'Build queue item cancelled')
            return (q.get('executable') or {}).get('number')
        number = wait(executable, 'queued demo build', 90)
    expect(type(number) is int and number > 0, 'Invalid build number')
    build = ITEM + '/' + str(number)
    print(scenario, 'queued:', JENKINS + build + '/', flush=True)
    def pending():
        r = jenkins(build + '/wfapi/pendingInputActions', statuses=(200, 404))
        if r['status'] == 200:
            for a in json.loads(r['body']):
                if a.get('id') == 'Gitleaks-receipt':
                    return True
        current = jjson(build + '/api/json?tree=building,result')
        expect(current['building'], 'Build stopped before requesting scan: ' + str(current['result']))
    wait(pending, 'the fixed receipt input', 90)
    available = view('/api/plugins')
    cap = next(p for p in available['plugins'] if p['pluginId'] == 'gitleaks')
    expect(available['executionLocation'] == 'LINUX_RESTRICTED' and cap['state'] == 'READY' and
           fixture in cap['scenarios'], 'Restricted runner not ready for the requested fixture')
    request = view('/api/run', {'pluginId': 'gitleaks', 'scenarioId': fixture}, available['csrfToken'])
    run_id = request['runId']
    expect(re.fullmatch(r'web-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', run_id), 'Unexpected run ID')
    def finished_scan():
        r = view('/api/runs/' + run_id)
        if r['state'] == 'RUNNING':
            return None
        expect(r['state'] == 'COMPLETED', 'Real scan did not complete: ' + str(r.get('reason')))
        return r
    scan = wait(finished_scan, 'the new scanner result', 40, .6)
    expect(scan['runId'] == run_id and scan['scannerExecuted'] is True and scan['evidenceClass'] == 'REAL'
           and scan['policyDecision'] == decision and scan['scannerExitCode'] == int(finding)
           and scan['findingsCount'] == int(finding) and scan['evaluationCount'] == 1
           and scan['cleanup'] == 'VERIFIED' and scan['releaseCount'] == scan['rolloutCount'] == 0,
           'Scanner result failed expected real-execution invariants')
    payload = {'job': JOB, 'build': str(number), 'scenario': scenario, 'scan': {k: scan[k] for k in FIELDS}}
    save(scenario.lower() + '-' + str(number) + '-scan.json', payload)
    signer.stdin.write(json.dumps(payload, separators=(',', ':')) + '\n')
    signer.stdin.flush()
    receipt = signer.stdout.readline().strip()
    expect(re.fullmatch(r'[A-Za-z0-9_-]{1,3900}\.[A-Za-z0-9_-]{86}', receipt), 'Signing failed')
    input_path = build + '/input/Gitleaks-receipt/proceed'
    jenkins(input_path, 'POST', urlencode({'json': json.dumps({'parameter': [
        {'name': 'SIGNED_RECEIPT', 'value': receipt}]}, separators=(',', ':'))}), FORM, (200, 302, 303))
    def finished_build():
        r = jjson(build + '/api/json?tree=building,result,artifacts[relativePath]')
        return r if not r['building'] else None
    final = wait(finished_build, 'Jenkins gate result', 110)
    stages = jjson(build + '/wfapi/describe')['stages']
    states = {s['name']: s['status'] for s in stages}
    log = jenkins(build + '/consoleText')['body']
    expect(final['result'] == expected, 'Unexpected Jenkins result: ' + str(final['result']))
    if finding:
        expect('Gitleaks Policy FAIL: verified controlled finding; blocking Demo Publish' in log and
               'Stage "Demo Publish" skipped due to earlier failure(s)' in log and
               'Demo Publish reached;' not in log, 'Gate did not prove expected publish skip')
    else:
        expect('Gitleaks Policy PASS: verified clean fixture' in log and
               'Demo Publish reached; no image, GitOps or deployment action' in log, 'Clean did not pass Demo Publish')
    expect([a['relativePath'] for a in final['artifacts']] == ['verified-gitleaks-receipt.json'],
           'Verified receipt is not the sole archive')
    archived = jjson(build + '/artifact/verified-gitleaks-receipt.json')
    expect(archived == payload, 'Archived receipt differs from the actual scan')
    proof = {'url': JENKINS + build + '/', 'result': final['result'], 'stages': states,
             'publishSkipped': finding, 'verifiedReceipt': archived,
             'releaseCount': 0, 'rolloutCount': 0}
    save(scenario.lower() + '-' + str(number) + '-build.json', proof)
    print(scenario, final['result'], states, run_id, scan['resultDigest'], flush=True)
    return proof


def main():
    # A mode-0700 session survives an interrupted operator for safe targeted resumption.
    session = tempfile.mkdtemp(prefix='gitleaks-demo-', dir='/tmp')
    print('Private signing session:', session, flush=True)
    execute(session)
    os.unlink(Path(session) / 'signer.pem')
    os.rmdir(session)


def execute(tempdir):
    p = subprocess.Popen(['/opt/homebrew/bin/node', '--input-type=module', '-e', SIGNER,
                          str(Path(tempdir) / 'signer.pem'), 'new'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        key = p.stdout.readline().strip()
        expect(re.fullmatch(r'[A-Za-z0-9+/]{59}=', key), 'Invalid verifier public key')
        source = (ROOT / 'infra/jenkins/gitleaks-demo/Pipeline.groovy').read_text()
        expect(source.count('@RECEIPT_PUBLIC_KEY@') == 1, 'Invalid pipeline template')
        pipeline = source.replace('@RECEIPT_PUBLIC_KEY@', key)
        r = jenkins(ITEM + '/api/json', statuses=(200, 404))
        repairing = r['status'] == 200
        if repairing:
            installed = XML.fromstring(jenkins(ITEM + '/config.xml')['body'])
            installed_hash = hashlib.sha256(installed.findtext('definition/script').encode()).hexdigest()
            known_hashes = [json.loads(f.read_text()).get('pipelineSha256')
                           for f in OUT.glob('*definition*.json')]
            expect(installed_hash in known_hashes, 'Unknown demo configuration; refuse overwrite')
            builds = jjson(ITEM + '/api/json?tree=builds[number,building,result]')['builds']
            expect(not any(b['building'] for b in builds), 'An existing demo build is still active')
        lint = jenkins('/pipeline-model-converter/validate', 'POST', urlencode({'jenkinsfile': pipeline}), FORM)
        expect('Jenkinsfile successfully validated' in lint['body'], 'Declarative validation failed: ' + lint['body'][:900])
        cfg = XML.Element('flow-definition')
        XML.SubElement(cfg, 'description').text = ('Isolated Gitleaks gate demonstration. Requires the bounded Mac '
            'operator dispatcher. Only fixed Clean and Finding fixtures. Demo Publish has no external side effects.')
        XML.SubElement(cfg, 'keepDependencies').text = 'false'
        prop = XML.SubElement(XML.SubElement(cfg, 'properties'), 'hudson.model.ParametersDefinitionProperty')
        choice = XML.SubElement(XML.SubElement(prop, 'parameterDefinitions'), 'hudson.model.ChoiceParameterDefinition')
        XML.SubElement(choice, 'name').text = 'SCENARIO'
        XML.SubElement(choice, 'description').text = 'Fixed non-production fixture'
        choices = XML.SubElement(choice, 'choices', {'class': 'java.util.ArrayList'})
        for scenario in ('Clean', 'Finding'):
            XML.SubElement(choices, 'string').text = scenario
        d = XML.SubElement(cfg, 'definition', {'class': 'org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition'})
        XML.SubElement(d, 'script').text = pipeline
        XML.SubElement(d, 'sandbox').text = 'true'
        XML.SubElement(cfg, 'triggers')
        XML.SubElement(cfg, 'disabled').text = 'false'
        save('ready-definition-' + str(time.time_ns()) + '.json', {'pipelineSha256': hashlib.sha256(pipeline.encode()).hexdigest(),
             'publicKeySpki': key, 'lint': lint['body'].strip()})
        endpoint = ITEM + '/config.xml' if repairing else '/createItem?name=' + JOB
        jenkins(endpoint, 'POST', XML.tostring(cfg, encoding='unicode'), 'application/xml', (200, 201, 302))
        actual = XML.fromstring(jenkins(ITEM + '/config.xml')['body'])
        expect(actual.findtext('definition/script') == pipeline and actual.findtext('definition/sandbox') == 'true'
               and not len(actual.findall('triggers/*'))
               and [v.text for v in actual.findall('.//choices/string')] == ['Clean', 'Finding'], 'Installed definition failed identity check')
        print('Configured and verified', JENKINS + ITEM + '/', flush=True)
        run('Clean', p)
        run('Finding', p)
    finally:
        p.stdin.close()
        p.wait(timeout=5)


def resume_clean(key_path, number):
    p = subprocess.Popen(['/opt/homebrew/bin/node', '--input-type=module', '-e', SIGNER, key_path, 'existing'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        key = p.stdout.readline().strip()
        installed = XML.fromstring(jenkins(ITEM + '/config.xml')['body'])
        expected = json.loads((OUT / 'ready-definition.json').read_text())
        expect(expected['publicKeySpki'] == key and hashlib.sha256(
            installed.findtext('definition/script').encode()).hexdigest() == expected['pipelineSha256'],
            'Cannot resume: job or signing key differs')
        run('Clean', p, number)
        run('Finding', p)
    finally:
        p.stdin.close()
        p.wait(timeout=5)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'resume-clean':
        resume_clean(sys.argv[2], int(sys.argv[3]))
    else:
        main()
