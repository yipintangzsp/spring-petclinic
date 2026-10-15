// Download pinned security packages before BuildKit, with bounded retries.
import { createHash } from 'node:crypto';
import { readFile, mkdir, rename, rm } from 'node:fs/promises';
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
    const temporary = new URL(path.href + '.part');
    try {
      const options = ['-fLsS', '--retry', '1', '--retry-all-errors', '--connect-timeout', '10',
        '--max-time', '90', '--output', temporary.pathname];
      if (process.env.PACKAGE_HTTPS_PROXY) options.push('--proxy', process.env.PACKAGE_HTTPS_PROXY);
      await exec('curl', [...options, url.href], { timeout: 200000, maxBuffer: 8192 });
      const digest = createHash('sha256').update(await readFile(temporary)).digest('hex');
      if (digest !== artifact.sha256) throw new Error('Security package SHA256 mismatch: ' + artifact.package);
      await rename(temporary, path);
      console.log(`${architecture} ${artifact.package} ${artifact.version} sha256:${digest}`);
    } finally {
      await rm(temporary, { force: true });
    }
  }));
  }
}
