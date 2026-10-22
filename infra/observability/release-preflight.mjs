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
 if (requiredNodes.includes('devops')) {
  const host = s.hostSample, age = now / 1000 - host?.at, mac = host?.mac;
  if (!Number.isFinite(age) || age < -5 || age > 90) blockers.push('devops: FRESH_HOST_MEASUREMENT_REQUIRED');
  if (!(mac?.diskFreeMiB >= 16384)) blockers.push('devops: MAC_DISK_BELOW_16_GIB');
  if (!(mac?.freePercent >= 10)) blockers.push('devops: MAC_MEMORY_BELOW_10_PERCENT');
  if (!Number.isFinite(mac?.efiAllocatedMiB) || mac.efiAllocatedMiB > 128)
   blockers.push('devops: EFI_ALLOCATION_REQUIRES_MAINTENANCE');
 }
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
  const storage = s.storage?.[name];
  for (const [kind, stats] of Object.entries({nodefs: storage?.fs, imagefs: storage?.runtime?.imageFs})) {
   const age = (now - Date.parse(stats?.time)) / 1000;
   const capacity = stats?.capacityBytes, available = stats?.availableBytes;
   const required = capacity * 0.15 + 8 * 1024 ** 3;
   if (!Number.isFinite(age) || age < -5 || age > 90 || !(capacity > 0) || !Number.isFinite(available))
    blockers.push(`${name}: ${kind} FRESH_DISK_MEASUREMENT_REQUIRED`);
   else if (available < required)
    blockers.push(`${name}: ${kind} DISK_HEADROOM: available=${available}, required=${Math.ceil(required)}`);
  }
  nodes.push({name, storage, leaseAgeSeconds, renewTime: lease?.spec.renewTime, conditions,
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
 return {ok: blockers.length === 0, blockers, nodes, hostSample: s.hostSample, scannerMetadata: s.scannerMetadata, targetNodes: requiredNodes,
  excludedNodes: s.nodes.filter(n => !requiredNodes.includes(n.metadata.name)).map(n => ({name:n.metadata.name,conditions:n.status.conditions,renewTime:s.leases.find(l=>l.metadata.name===n.metadata.name)?.spec.renewTime})), desired, available,
  pods: s.pods.map(p => ({name: p.metadata.name, uid: p.metadata.uid, node: p.spec.nodeName,
   deletionTimestamp: p.metadata.deletionTimestamp, ready: ready.includes(p)})),
  readyEndpointPods: endpointPods.size};
}

export function requireHarborRegistry(slices) {
 for (const name of ['http-registry', 'http-controller']) {
  const healthy = slices.some(slice => slice.ports?.some(port => port.name === name)
   && slice.endpoints?.some(endpoint => endpoint.conditions?.ready === true
    && endpoint.conditions?.terminating !== true));
  if (!healthy) throw Error(`PREFLIGHT_HARBOR_REGISTRY_UNAVAILABLE: ${name}`);
 }
}

export function requireFreshScannerMetadata(databases, now = Date.now()) {
 for (const [kind, version] of [['db', 2], ['java-db', 1]]) {
  const metadata = databases?.[kind];
  const next = Date.parse(metadata?.NextUpdate), downloaded = Date.parse(metadata?.DownloadedAt);
  const updated = Date.parse(metadata?.UpdatedAt);
  if (metadata?.Version !== version || !Number.isFinite(next) || next <= now
   || !Number.isFinite(downloaded) || downloaded <= 0 || downloaded > now + 300000
   || !Number.isFinite(updated) || updated > now + 300000)
   throw Error(`PREFLIGHT_SCANNER_DATABASE_REFRESH_REQUIRED: ${kind}`);
 }
}

export async function preflight({output = 'target/platform/preflight.json', windowMs = 30000, pollMs = 5000, collect} = {}) {
 const samples = [], started = Date.now(); let failure;
 function kube(args, input) {
  const r = spawnSync('kubectl', ['--request-timeout=5s', ...args, '-o', 'json'],
   {input, encoding: 'utf8', timeout: 6000, maxBuffer: 4 * 1024 * 1024});
  if (r.status !== 0) throw Error(`PREFLIGHT_API_ERROR: ${args.join(' ')}: ${r.error?.message || r.stderr.trim()}`);
  return JSON.parse(r.stdout);
 }
 collect ??= () => {
  const nodes=kube(['get','nodes']).items;
  requireHarborRegistry(kube(['-n','harbor','get','endpointslices','-l','kubernetes.io/service-name=harbor-registry']).items);
  const scannerMetadata = {};
  for (const kind of ['db', 'java-db']) {
   const result = spawnSync('kubectl', ['--request-timeout=5s', '-n', 'harbor', 'exec', 'harbor-trivy-0', '-c', 'trivy',
    '--', 'cat', `/home/scanner/.cache/trivy/${kind}/metadata.json`], {encoding:'utf8',timeout:10000});
   if (result.status !== 0) throw Error(`PREFLIGHT_SCANNER_DATABASE_UNAVAILABLE: ${kind}`);
   scannerMetadata[kind] = JSON.parse(result.stdout);
  }
  requireFreshScannerMetadata(scannerMetadata);

  // kubectl create emits concatenated JSON for multi-document input. Parse only
  // the single Deployment document through kubectl's YAML decoder.
  const documents=fs.readFileSync('k8s/production/petclinic.yaml','utf8').split(/^---\s*$/m).filter(x=>/^kind:\s*Deployment\s*$/m.test(x));
  if(documents.length!==1)throw Error('Exactly one planned production Deployment required');
  const d=kube(['create','--dry-run=client','--validate=false','-f','-'],documents[0]);
  if(d.kind!=='Deployment'||d.metadata.name!=='petclinic')throw Error('Planned production Deployment missing');
  const selector=d.spec.template.spec.nodeSelector;
  if(!selector||!Object.keys(selector).length)throw Error('Explicit measured target selection required');
  const targetNodes=nodes.filter(n=>Object.entries(selector).every(([key,value])=>n.metadata.labels[key]===value)).map(n=>n.metadata.name);
  const storage = {};
  for (const name of targetNodes) {
   const result = spawnSync('kubectl', ['--request-timeout=5s', 'get', '--raw', `/api/v1/nodes/${name}/proxy/stats/summary`],
    {encoding: 'utf8', timeout: 6000, maxBuffer: 4 * 1024 * 1024});
   if (result.status !== 0) throw Error(`PREFLIGHT_DISK_API_ERROR: ${name}`);
   const node = JSON.parse(result.stdout).node;
   storage[name] = {fs: node.fs, runtime: node.runtime};
  }
  const hostSample = targetNodes.includes('devops') ? JSON.parse(kube(['-n','data-infra','get','configmap','platform-host-resources']).data['sample.json']) : undefined;
  return {nodes,targetNodes,storage,hostSample,scannerMetadata,
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
