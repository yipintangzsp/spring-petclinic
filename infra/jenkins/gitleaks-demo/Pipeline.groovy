// Only admin can configure this demo or submit its signed scan receipt.
pipeline {
  agent none
  options {
    skipDefaultCheckout(true)
    disableConcurrentBuilds()
    disableRestartFromStage()
    timeout(time: 8, unit: 'MINUTES')
  }
  parameters {
    choice(name: 'SCENARIO', choices: ['Clean', 'Finding'], description: 'Fixed non-production fixture')
  }
  stages {
    stage('Await Restricted Linux Scan') {
      steps {
        script {
          if (!(params.SCENARIO in ['Clean', 'Finding'])) { error('Unsupported fixed scenario') }
          env.GITLEAKS_DEMO_RECEIPT = input(
            id: 'gitleaks-receipt', message: 'Awaiting signed receipt from the local Security Manager operator',
            submitter: 'admin', parameters: [text(name: 'SIGNED_RECEIPT', defaultValue: '')])
          if (!(env.GITLEAKS_DEMO_RECEIPT ==~ /[A-Za-z0-9_-]{1,3900}\.[A-Za-z0-9_-]{86}/)) {
            error('Invalid signed receipt format')
          }
        }
      }
    }
    stage('Gitleaks Gate') {
      agent { label 'built-in' }
      steps {
        script {
          dir("verified-receipt-${env.BUILD_NUMBER}") {
            try {
              def decision = sh(returnStdout: true, script: '''#!/bin/sh
set -eu
umask 077
/usr/bin/env -i /usr/bin/node --input-type=module - "$GITLEAKS_DEMO_RECEIPT" "$JOB_NAME" "$BUILD_NUMBER" "$SCENARIO" <<'NODE'
import { createPublicKey, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const [receipt, job, build, scenario] = process.argv.slice(2);
const require = (ok, why) => { if (!ok) throw new Error(why); };
require(job === 'security-gitleaks-demo' && /^[1-9][0-9]*$/.test(build), 'Unexpected Jenkins build');
require(scenario === 'Clean' || scenario === 'Finding', 'Unsupported fixed scenario');
require(/^[A-Za-z0-9_-]{1,3900}[.][A-Za-z0-9_-]{86}$/.test(receipt), 'Invalid receipt encoding');
const [body, signature] = receipt.split('.').map(value => Buffer.from(value, 'base64url'));
const key = createPublicKey({ key: Buffer.from('@RECEIPT_PUBLIC_KEY@', 'base64'), format: 'der', type: 'spki' });
require(verify(null, body, key, signature), 'Untrusted scan receipt');
const { job: boundJob, build: boundBuild, scenario: boundScenario, scan } = JSON.parse(body);
const finding = scenario === 'Finding';
require(boundJob === job && boundBuild === build && boundScenario === scenario, 'Receipt does not belong to this build');
require(scan.pluginId === 'gitleaks' && scan.scenarioId === (finding ? 'controlled-finding' : 'clean') &&
  /^web-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(scan.runId), 'Unexpected scan identity');
require(scan.evidenceClass === 'REAL' && scan.state === 'COMPLETED' && scan.scannerExecuted === true &&
  scan.executionHost === 'devops/192.168.64.11' && scan.executionIdentity === 'security-gitleaks (UID/GID 24021)' &&
  scan.toolVersion === 'v8.30.1' && scan.toolSha256 === 'db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d',
  'Unexpected scanner provenance');
require(scan.evaluationCount === 1 && scan.scannerExitCode === (finding ? 1 : 0) &&
  scan.findingsCount === (finding ? 1 : 0) && scan.policyDecision === (finding ? 'FAIL' : 'PASS'),
  'Unexpected scan or Policy result');
require(['resultDigest', 'rawReportDigest', 'factDigest'].every(key =>
  typeof scan[key] === 'string' && /^[0-9a-f]{64}$/.test(scan[key])) &&
  Date.parse(scan.scannerStartedAt) <= Date.parse(scan.scannerCompletedAt), 'Missing scan evidence');
writeFileSync('verified-gitleaks-receipt.json', JSON.stringify(JSON.parse(body), null, 2) + String.fromCharCode(10),
  { flag: 'wx', mode: 0o600 });
console.log(scan.policyDecision);
NODE
''').trim()
              archiveArtifacts artifacts: 'verified-gitleaks-receipt.json', allowEmptyArchive: false
              if (decision == 'FAIL') { error('Gitleaks Policy FAIL: verified controlled finding; blocking Demo Publish') }
              if (decision != 'PASS') { error('Invalid gate decision') }
              echo 'Gitleaks Policy PASS: verified clean fixture'
            } finally {
              deleteDir()
            }
          }
        }
      }
    }
    stage('Demo Publish') {
      steps { echo 'Demo Publish reached; no image, GitOps or deployment action' }
    }
  }
}
