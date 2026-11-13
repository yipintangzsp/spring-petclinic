import fs from 'node:fs';
// Use only the existing, scoped Jenkins Sonar credential binding.
const token = process.env.SONAR_TOKEN;
if (!token) throw Error('Sonar credential binding is absent');
const host = process.env.SONAR_HOST_URL;
if (!host) throw Error('Sonar host is absent');
async function get(path) {
  const response = await fetch(new URL(path, host), {
    headers: {Authorization: `Bearer ${token}`}, signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw Error(`Sonar diagnostics HTTP ${response.status}`);
  return response.json();
}
const gate = await get('/api/qualitygates/project_status?projectKey=petclinic');
const issues = await get('/api/issues/search?componentKeys=petclinic&resolved=false&ps=100');
const result = {
  gate: gate.projectStatus,
  totalIssues: issues.total,
  issues: issues.issues.map(({key, rule, severity, component, line, message, status}) =>
    ({key, rule, severity, component, line, message, status}))
};
fs.mkdirSync('target/platform', {recursive:true});
fs.writeFileSync('target/platform/sonar-quality.json', JSON.stringify(result, null, 2));
console.log(JSON.stringify(result));
