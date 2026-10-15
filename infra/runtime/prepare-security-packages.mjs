// Download pinned security packages before BuildKit, with bounded retries.
import { readFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { materializePackage } from './security-package-cache.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const lock = JSON.parse(await readFile(new URL('./openssl-packages.json', import.meta.url)));
const destination = new URL('../../target/security-packages/', import.meta.url);
for (const [architecture, packages] of Object.entries(lock)) {
  const directory = new URL(architecture + '/', destination);
  await mkdir(directory, { recursive: true });
  // At most three small curl processes, and one architecture at a time.
  for (let index = 0; index < packages.length; index += 3) {
  await Promise.all(packages.slice(index, index + 3).map(async artifact => {
    const url = new URL(artifact.url);
    if (url.protocol !== 'https:' || !['ports.ubuntu.com', 'archive.ubuntu.com'].includes(url.hostname)
        || !/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new Error('Invalid security package source');
    const path = new URL(url.pathname.split('/').pop(), directory);
    const cacheFile = join(process.env.SECURITY_PACKAGE_CACHE_DIR ||
      join(homedir(), '.cache', 'petclinic-security-packages'), artifact.sha256 + '.deb');
    const result = await materializePackage({ sha256: artifact.sha256, cacheFile,
      outputFile: path.pathname, download: async temporary => {
        const options = ['-fLsS', '--retry', '1', '--retry-all-errors', '--connect-timeout', '10',
          '--max-time', '180', '--output', temporary];
        if (process.env.PACKAGE_HTTPS_PROXY) options.push('--proxy', process.env.PACKAGE_HTTPS_PROXY);
        await exec('curl', [...options, url.href], { timeout: 380000, maxBuffer: 8192 });
      } });
    console.log(`${architecture} ${artifact.package} ${artifact.version} sha256:${artifact.sha256} cache=${result.cacheHit ? 'verified' : 'downloaded'}`);
  }));
  }
}
