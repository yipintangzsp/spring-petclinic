import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

// These are the existing production nodes, not a cluster-wide scheduling policy.
export const productionNodes = ['devops', 'aliyun-worker', 'ucloud-worker'];
export function assessPreflight(s, now = Date.now()) {
 const blockers = [], nodes = [];
 const requiredNodes = s.targetNodes ?? productionNodes;
 if (!requiredNodes.length) blockers.push('NO_VERIFIED_TARGET_NODE');
 for (const name of requiredNodes) {
  const node = s.nodes.find(n => n.metadata.name === name);
  const lease = s.leases.find(l => l.metadata.name === name);
  const renewed = Date.parse(lease?.spec.renewTime);
  const leaseAgeSeconds = Number.isFinite(renewed) ? (now - renewed) / 1000 : null;
  const conditions = node?.status.conditions ?? [];
  if (!conditions.some(c => c.type === 'Ready' && c.status === 'True')) blockers.push(`${name}: NODE_NOT_READY`);
  for (const type of ['MemoryPressure', 'DiskPressure', 'PIDPressure']) {
   if (!conditions.some(c => c.type === type && c.status === 'False')) blockers.push(`${name}: ${type} not confirmed False`);
  }
  if (node?.spec.unschedulable) blockers.push(`${name}: NODE_CORDONED`);
  if (conditions.some(c => c.type === 'NetworkUnavailable' && c.status !== 'False')) blockers.push(`${name}: NETWORK_UNAVAILABLE`);
  if (node?.spec.taints?.some(t => ['node.kubernetes.io/not-ready', 'node.kubernetes.io/unreachable'].includes(t.key)))
   blockers.push(`${name}: UNHEALTHY_NODE_TAINT`);
  if (leaseAgeSeconds === null || leaseAgeSeconds > 40 || leaseAgeSeconds < -5) blockers.push(`${name}: LEASE_NOT_FRESH`);
  nodes.push({name, leaseAgeSeconds, renewTime: lease?.spec.renewTime, conditions,
   allocatable: node?.status.allocatable, taints: node?.spec.taints ?? []});
 }
 const ready = s.pods.filter(p => !p.metadata.deletionTimestamp &&
  p.status.conditions?.some(c => c.type === 'Ready' && c.status === 'True') &&
  s.nodes.some(n => n.metadata.name === p.spec.nodeName && n.status.conditions.some(c => c.type === 'Ready' && c.status === 'True')) &&
  s.leases.some(l => l.metadata.name === p.spec.nodeName && now - Date.parse(l.spec.renewTime) <= 40000));
 const endpoints = s.slices.flatMap(x => x.endpoints ?? []).filter(e => e.conditions?.ready === true &&
  e.conditions?.terminating !== true && e.conditions?.serving !== false &&
  ready.some(p => p.metadata.uid === e.targetRef?.uid && p.spec.nodeName === e.nodeName));
 const desired = s.deployment.spec.replicas ?? 1;
 const available = s.deployment.status.availableReplicas ?? 0;
 const endpointPods = new Set(endpoints.map(e => e.targetRef.uid));
 if (ready.length < desired || available < desired || endpointPods.size < desired)
  blockers.push(`BUSINESS_CAPACITY: desired=${desired}, ready=${ready.length}, available=${available}, endpointPods=${endpointPods.size}`);
 return {ok: blockers.length === 0, blockers, nodes, targetNodes: requiredNodes,
  excludedNodes: s.nodes.filter(n => !requiredNodes.includes(n.metadata.name)).map(n => ({name:n.metadata.name,conditions:n.status.conditions,renewTime:s.leases.find(l=>l.metadata.name===n.metadata.name)?.spec.renewTime})), desired, available,
  pods: s.pods.map(p => ({name: p.metadata.name, uid: p.metadata.uid, node: p.spec.nodeName,
   deletionTimestamp: p.metadata.deletionTimestamp, ready: ready.includes(p)})),
  readyEndpointPods: endpointPods.size};
}

export async function preflight({output = 'target/platform/preflight.json', windowMs = 30000, pollMs = 5000, collect} = {}) {
 const samples = [], started = Date.now(); let failure;
 function kube(args) {
  const r = spawnSync('kubectl', ['--request-timeout=5s', ...args, '-o', 'json'],
   {encoding: 'utf8', timeout: 6000, maxBuffer: 4 * 1024 * 1024});
  if (r.status !== 0) throw Error(`PREFLIGHT_API_ERROR: ${args.join(' ')}: ${r.error?.message || r.stderr.trim()}`);
  return JSON.parse(r.stdout);
 }
 collect ??= () => {
  const nodes=kube(['get','nodes']).items;
  const planned=kube(['create','--dry-run=client','--validate=false','-f','k8s/production/petclinic.yaml']);
  const d=(planned.items??[planned]).find(x=>x.kind==='Deployment'&&x.metadata.name==='petclinic');
  if(!d)throw Error('Planned production Deployment missing');
  const selector=d.spec.template.spec.nodeSelector;
  if(!selector||!Object.keys(selector).length)throw Error('Explicit measured target selection required');
  const targetNodes=nodes.filter(n=>Object.entries(selector).every(([key,value])=>n.metadata.labels[key]===value)).map(n=>n.metadata.name);
  return {nodes,targetNodes,
   leases:kube(['-n','kube-node-lease','get','leases']).items,
   pods:kube(['-n','petclinic','get','pods','-l','app=petclinic']).items,
   slices:kube(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic']).items,
   deployment:kube(['-n','petclinic','get','deployment','petclinic'])};
 };

 try {
  while (true) {
   const assessment = assessPreflight(await collect());
   samples.push({time: new Date().toISOString(), assessment});
   console.log(`RELEASE_PREFLIGHT ${JSON.stringify(assessment)}`);
   if (!assessment.ok) throw Error(`INFRASTRUCTURE_NOT_READY: ${assessment.blockers.join('; ')}`);
   if (Date.now() - started >= windowMs) {
    if (windowMs > 0 && samples.at(-1).assessment.nodes.map(n=>n.name).some(name =>
     samples.at(-1).assessment.nodes.find(n => n.name === name).renewTime === samples[0].assessment.nodes.find(n => n.name === name).renewTime))
     throw Error('LEASE_NOT_PROGRESSING: fresh timestamp alone does not prove connectivity');
    return assessment;
   }
   await new Promise(resolve => setTimeout(resolve, Math.min(pollMs, windowMs - (Date.now() - started))));
  }
 } catch (error) { failure = error.message; throw error; }
 finally {
  // Only selected resource metadata/status; no environments, credentials or business data.
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.writeFileSync(output, JSON.stringify({started: new Date(started).toISOString(), finished: new Date().toISOString(), failure, samples}, null, 2));
 }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
 preflight({output: process.argv[2] || undefined}).catch(error => {console.error(error.message); process.exitCode = 1;});
