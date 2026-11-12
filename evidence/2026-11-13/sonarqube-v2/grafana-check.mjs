import fs from 'node:fs';
import http from 'node:http';
import {execFileSync} from 'node:child_process';
const [runId, resultDigest, caseId, outFile] = process.argv.slice(2);
const token = execFileSync('/usr/bin/security', ['find-generic-password', '-s', 'petclinic-security-manager-v2-grafana', '-a', 'security-manager-v2-dashboard', '-w'], {encoding: 'utf8'}).trim();
const query = `{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"} | json | runId="${runId}" | resultDigest="${resultDigest}"`;
const now = Date.now();
const params = new URLSearchParams({query, start: String((now - 3600e3)) + '000000', end: String((now + 300e3)) + '000000', limit: '50'});
const url = `http://grafana.devops.local/api/datasources/uid/loki/resources/loki/api/v1/query_range?${params}`;
const res = await new Promise((resolve, reject) => {
  const req = http.get(url, {headers: {Authorization: 'Bearer ' + token}, timeout: 15000}, r => {
    const chunks = []; r.on('data', c => chunks.push(c)); r.on('end', () => resolve({status: r.statusCode, body: Buffer.concat(chunks).toString()}));
  });
  req.on('timeout', () => req.destroy(Error('TIMEOUT'))); req.on('error', reject);
});
let matched = 0, eventIdentity = null, plugin = null;
try {
  const d = JSON.parse(res.body);
  for (const s of d?.data?.result ?? []) { matched += s.values?.length ?? 0; const v = s.values?.[0]?.[1]; if (v) { const e = JSON.parse(v); eventIdentity = e.eventIdentity; plugin = e.pluginId; } }
} catch {}
const out = {via: 'grafana-datasource-proxy', datasourceUid: 'loki', httpStatus: res.status, query, runId, caseId, matched, eventIdentity, plugin, grafanaProxyMatched: matched > 0 && plugin === 'sonarqube'};
fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + '\n');
console.log('GRAFANA', caseId, res.status, 'matched=' + matched, 'ok=' + out.grafanaProxyMatched);
