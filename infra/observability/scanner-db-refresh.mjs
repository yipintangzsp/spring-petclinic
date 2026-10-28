import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const kinds = {db: 2, 'java-db': 1};
function validFields(m, version, now) {
 return m?.Version === version && Number.isFinite(Date.parse(m.NextUpdate))
  && Number.isFinite(Date.parse(m.UpdatedAt)) && Date.parse(m.UpdatedAt) <= now + 300000
  && Number.isFinite(Date.parse(m.DownloadedAt)) && Date.parse(m.DownloadedAt) > 0
  && Date.parse(m.DownloadedAt) <= now + 300000;
}
export function requireFreshScannerMetadata(databases, now = Date.now()) {
 for (const [kind, version] of Object.entries(kinds))
  if (!validFields(databases?.[kind], version, now) || Date.parse(databases[kind].NextUpdate) <= now)
   throw Error(`PREFLIGHT_SCANNER_DATABASE_REFRESH_REQUIRED: ${kind}`);
}
export function verifyManifest(kind, bytes, claimedDigest) {
 if (!(kind in kinds)) throw Error('Unsupported scanner database');
 const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
 if (digest !== claimedDigest) throw Error('Official scanner manifest digest mismatch');
 const manifest = JSON.parse(bytes), layer = manifest.layers?.[0];
 const media = `application/vnd.aquasec.trivy.${kind === 'db' ? 'db' : 'javadb'}.layer.v1.tar+gzip`;
 if (manifest.schemaVersion !== 2 || manifest.layers?.length !== 1 || layer.mediaType !== media
  || !/^sha256:[a-f0-9]{64}$/.test(layer.digest) || !(layer.size > 0 && layer.size <= 1610612736))
  throw Error('Unexpected official scanner artifact');
 return {kind, digest, layer, repository: `ghcr.nju.edu.cn/aquasecurity/trivy-${kind}@${digest}`};
}
export async function ensureScannerDatabases(metadata, io, now = Date.now()) {
 const current = structuredClone(metadata), actions = [];
 for (const [kind, version] of Object.entries(kinds)) {
  const evaluatedAt = Math.max(now, Date.now());
  if (!validFields(current[kind], version, evaluatedAt)) throw Error(`SCANNER_METADATA_INVALID: ${kind}`);
  if (Date.parse(current[kind].NextUpdate) > evaluatedAt) continue;
  await io.assertOwner();
  const artifact = await io.upstream(kind);
  const log = await io.download(kind, artifact);
  current[kind] = await io.read(kind);
  if (!validFields(current[kind], version, Date.now()) || Date.parse(current[kind].NextUpdate) <= Date.now())
   throw Error(`SCANNER_REFRESH_DID_NOT_PRODUCE_FRESH_DATABASE: ${kind}`);
  const action = {kind, artifact, metadata: current[kind], log};
  actions.push(action); io.record?.(action);
 }
 requireFreshScannerMetadata(current);
 return {metadata: current, actions};
}
function kube(args, timeout = 12000) {
 return execFileSync('kubectl', ['--request-timeout=10s', ...args], {encoding:'utf8',timeout,maxBuffer:2097152});
}
export function fetchOfficialCurl(args, url, config, proxy, runner = execFileSync) {
 const options = {input:config,timeout:50000,maxBuffer:1048576};
 const routes = proxy ? [['--proxy',proxy],['--noproxy','*']] : [['--noproxy','*']];
 for (const route of routes) {
  try { return runner('curl',[...args,...route,url],options); }
  catch { /* A route failure is not a successful fetch. */ }
 }
 throw Error('OFFICIAL_SCANNER_MANIFEST_FETCH_FAILED');
}
export function scannerRefreshIO({cacheDir = '/home/scanner/.cache/trivy'} = {}) {
 if (!/^\/(home\/scanner\/\.cache\/trivy|tmp\/petclinic-db-check-[a-f0-9]+)$/.test(cacheDir)) throw Error('Unsafe scanner cache path');
 const cli = args => kube(['-n','harbor','exec','harbor-trivy-0','-c','trivy','--',...args]);
 return {
  assertOwner() {
   const holder = process.env.HEAVY_HOLDER || `jenkins-petclinic-${process.env.BUILD_NUMBER}`;
   if (holder.endsWith('undefined')) throw Error('Scanner refresh requires an explicit owned heavy Lease');
   const lease = JSON.parse(kube(['-n','data-infra','get','lease','platform-heavy','-o','json']));
   if (lease.spec.holderIdentity !== holder) throw Error('Scanner refresh does not own the heavy Lease');
   const {node} = JSON.parse(kube(['get','--raw','/api/v1/nodes/devops/proxy/stats/summary']));
   for (const stats of [node.fs,node.runtime.imageFs]) {
    const age = Date.now() - Date.parse(stats.time);
    if (age < -5000 || age > 90000 || stats.availableBytes < stats.capacityBytes * 0.15 + 12 * 1024 ** 3)
     throw Error('Scanner refresh requires fresh disk headroom plus 4 GiB temporary allowance');
   }
   if (cli(['ps','-o','comm']).split('\n').some(line => line.trim() === 'trivy'))
    throw Error('Another scanner CLI is active; preserve it');
  },
  upstream(kind) {
   const repo = `aquasecurity/trivy-${kind}`, dir = fs.mkdtempSync(path.join(os.tmpdir(),'clinic-db-manifest-'));
   function curl(url, config = '', headers) {
    const args = ['-fLsS','--retry','1','--connect-timeout','8','--max-time','20'];
    if (headers) args.push('--dump-header',headers);
    if (config) args.push('--config','-');
    return fetchOfficialCurl(args,url,config,process.env.PACKAGE_HTTPS_PROXY);
   }
   try {
    const token = JSON.parse(curl(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`)).token;
    if (!new RegExp('^[A-Za-z0-9._~+/=-]+$').test(token)) throw Error('Invalid public registry token');
    const headers = path.join(dir,'headers');
    const bytes = curl(`https://ghcr.io/v2/${repo}/manifests/${kinds[kind]}`,
     `header = "Authorization: Bearer ${token}"\nheader = "Accept: application/vnd.oci.image.manifest.v1+json"\n`,headers);
    const digest = fs.readFileSync(headers,'utf8').split(/\r?\n/).filter(x=>/^docker-content-digest:/i.test(x)).at(-1)?.split(': ').slice(1).join(': ').trim();
    return verifyManifest(kind,bytes,digest);
   } finally {fs.rmSync(dir,{recursive:true,force:true});}
  },
  download(kind, artifact) {
   const nonce = randomBytes(12).toString('hex'), pidfile = `/tmp/petclinic-db-refresh-${nonce}.pid`;
   const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
   const args = ['env','HTTP_PROXY=','HTTPS_PROXY=','ALL_PROXY=','NO_PROXY=ghcr.nju.edu.cn',
    `PETCLINIC_DB_REFRESH_OWNER=${nonce}`,'trivy','image',
    kind === 'db' ? '--download-db-only' : '--download-java-db-only',
    kind === 'db' ? '--db-repository' : '--java-db-repository',artifact.repository,
    '--cache-dir',cacheDir,'--timeout','3m','--no-progress'];
   const script = `set -eu; umask 077; test ! -e ${pidfile}; echo $$ >${pidfile}; exec ${args.map(quote).join(' ')}`;
   let log;
   try {
    log = kube(['-n','harbor','exec','harbor-trivy-0','-c','trivy','--','sh','-c',script],210000);
    return log;
   } finally {
    // Only the process bearing this invocation's random owner token may be stopped.
    const stop = `if [ -f ${pidfile} ]; then p=$(cat ${pidfile}); if [ -r /proc/$p/environ ] && tr '\\000' '\\n' </proc/$p/environ | grep -Fxq PETCLINIC_DB_REFRESH_OWNER=${nonce}; then kill -TERM "$p"; fi; fi`;
    cli(['sh','-c',stop]);
    let stopped = false;
    for (let i=0;i<10;i++) {
     const check = `if [ -f ${pidfile} ]; then p=$(cat ${pidfile}); test ! -r /proc/$p/environ || ! tr '\\000' '\\n' </proc/$p/environ | grep -Fxq PETCLINIC_DB_REFRESH_OWNER=${nonce}; fi`;
     try {cli(['sh','-c',check]);stopped=true;break;} catch {execFileSync('sleep',['1']);}
    }
    if (!stopped) throw Error('Owned scanner updater remains active; inspect it before another build');
    cli(['rm','-f',pidfile]);
   }
  },
  read(kind) {return JSON.parse(cli(['cat',`${cacheDir}/${kind}/metadata.json`]));}
 };
}
