// Falco V2 candidate driver (devops, Linux). Evidence reproduction script;
// not part of the platform runtime. Modes:
//   node falco-v2-driver.mjs run <runId> <testPod> <windowEndMs> <outBase>
//   node falco-v2-driver.mjs disabled <runId> <outBase>
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {runCandidate} from './infra/security/manager-v2/core.mjs';
import {realFalcoRegistry} from './infra/security/manager-v2/registry.mjs';
import {routeResults, routeResultsWithLoki, CONSUMERS} from './infra/security/manager-v2/router.mjs';
import {createLokiTransport} from './infra/security/manager-v2/consumers/loki.mjs';

const [mode, runId, a, b, c] = process.argv.slice(2);
const registry = realFalcoRegistry();
const allPlugins = enabledId => Object.fromEntries(registry.ids().map(id => [id, {enabled: id === enabledId}]));
const baseConfig = plugins => ({security: {enabled: true, globalMode: 'audit', securityLevel: 'standard', profile: 'infra-k8s', plugins}});
const context = {platform: 'linux', capabilities: {RUNTIME_TARGET: {state: 'AVAILABLE'}}};

async function disabledRuns(outBase) {
  const out = [];
  const cases = [
    ['plugin', baseConfig(allPlugins(null))],
    ['master', {security: {enabled: false, globalMode: 'audit', securityLevel: 'standard', profile: 'infra-k8s', plugins: allPlugins('falco')}}],
  ];
  for (const [name, config] of cases) {
    const id = runId + '-' + name;
    fs.mkdirSync(outBase + '-' + name, {recursive: true, mode: 0o700});
    const run = await runCandidate({registry, runId: id, projectId: 'petclinic-runtime', context, inputs: {}, config, output: outBase + '-' + name + '/artifact'});
    const sel = run.gate.falco;
    out.push({case: name, runId: id, executionStatus: sel.executionStatus, policyDecision: sel.policyDecision, evaluationCount: sel.evaluationCount, failureReason: typeof sel.failureReason === 'string' ? sel.failureReason : null, resultDigest: sel.resultDigest, artifactDigest: run.artifact.sealDigest, policyEvaluationCounts: run.policyEvaluationCounts});
  }
  console.log(JSON.stringify({kind: 'FalcoDisabledRuns', runs: out}, null, 2));
}

async function lokiQuery(runId2, resultDigest, completedAtMs) {
  const selector = '{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"}';
  const query = selector + ' | json | runId=' + JSON.stringify(runId2) + ' | resultDigest=' + JSON.stringify(resultDigest);
  const at = BigInt(completedAtMs) * 1000000n;
  const url = 'http://10.43.7.197:3100/loki/api/v1/query_range?' + new URLSearchParams({query, start: String(at - 120000000000n), end: String(at + 120000000000n), limit: '5', direction: 'forward'});
  const r = await fetch(url, {signal: AbortSignal.timeout(8000)});
  const body = await r.json();
  const matches = (body.data?.result ?? []).flatMap(s => s.values.map(v => JSON.parse(v[1])));
  return {httpStatus: r.status, matched: matches.length, event: matches[0] ?? null};
}

async function realRun(testPod, windowEndMs, outBase) {
  // publishLoki real-http posts to 127.0.0.1:32189 (the Mac channel port);
  // on devops we provide the same loopback contract with a plain TCP
  // forwarder to the in-cluster Loki service, then tear it down.
  const server = net.createServer(sock => {
    const up = net.connect(3100, '10.43.7.197');
    sock.pipe(up); up.pipe(sock);
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(32189, '127.0.0.1', resolve); });
  try {
    fs.mkdirSync(outBase, {recursive: true, mode: 0o700});
    const run = await runCandidate({
      registry, runId, projectId: 'petclinic-runtime', context,
      inputs: {falco: {targetId: 'devops-falco-sensor', testPod, windowEndMs}},
      config: baseConfig(allPlugins('falco')), output: outBase + '/artifact',
    });
    const sel = run.gate.falco;
    fs.mkdirSync(outBase + '/router', {mode: 0o700});
    const routed = routeResults({run, artifactDirectory: outBase + '/artifact', expectedSealDigest: run.artifact.sealDigest, output: outBase + '/router', definitions: CONSUMERS.filter(x => x.consumerId !== 'defectdojo-future')});
    fs.mkdirSync(outBase + '/loki', {mode: 0o700});
    const withLoki = await routeResultsWithLoki({
      run: {summary: run.summary}, artifactDirectory: outBase + '/artifact', expectedSealDigest: run.artifact.sealDigest,
      definitions: [], expectedProjectId: 'petclinic-runtime', singlePluginId: 'falco', freshRunId: runId,
      lokiOutput: outBase + '/loki',
      lokiTransport: createLokiTransport({mode: 'real-http', targetId: 'existing-security-loki-v1', timeoutMs: 3000, maxAttempts: 1, backoffMs: 1}),
    });
    const receipt = withLoki.lokiDelivery;
    let query = null;
    if (receipt.deliveryState === 'ACKNOWLEDGED') {
      for (let i = 0; i < 3 && !query?.matched; i++) {
        query = await lokiQuery(runId, sel.resultDigest, Date.parse(sel.completedAt));
        if (!query.matched) await new Promise(r => setTimeout(r, 400));
      }
    }
    console.log(JSON.stringify({
      kind: 'FalcoRealRun', runId, testPod, windowEndMs,
      executionStatus: sel.executionStatus, policyDecision: sel.policyDecision,
      evaluationCount: sel.evaluationCount, failureReason: sel.failureReason ?? null,
      resultDigest: sel.resultDigest, artifactDigest: run.artifact.sealDigest,
      overallStatus: run.summary.overallStatus,
      policyEvaluationCounts: run.policyEvaluationCounts,
      detectedCount: sel.runtimeFacts?.detectedCount ?? null,
      detectedEvents: sel.runtimeFacts?.detectedEvents ?? null,
      sensor: sel.runtimeFacts?.sensor ?? null,
      cleanup: sel.cleanup ?? null, completedAt: sel.completedAt,
      router: routed.receipts.map(r => ({consumerId: r.consumerId, deliveryDecision: r.deliveryDecision})),
      loki: {deliveryState: receipt.deliveryState, httpStatus: receipt.httpStatus ?? null, httpRequestCount: receipt.httpRequestCount ?? null, errorCategory: receipt.errorCategory ?? null, diagnosticCode: receipt.diagnosticCode ?? null, receiptDigest: receipt.receiptDigest},
      lokiQuery: query,
    }, null, 2));
  } finally {
    await new Promise(r => server.close(r));
  }
}

if (mode === 'disabled') await disabledRuns(a);
else if (mode === 'run') await realRun(a, Number(b), c);
else { console.error('unknown mode'); process.exit(2); }
