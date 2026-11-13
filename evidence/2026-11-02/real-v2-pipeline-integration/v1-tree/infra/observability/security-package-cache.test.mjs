import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { materializePackage } from '../runtime/security-package-cache.mjs';

for (const scenario of ['reused after build clean', 'corrupted cache', 'untrusted download']) {
  test(`security package ${scenario}`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'clinic-package-'));
    const bytes = Buffer.from('pinned package artifact');
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const cacheFile = join(root, 'cache.deb'), outputFile = join(root, 'build', 'package.deb');
    let downloads = 0;
    const options = { sha256, cacheFile, outputFile, download: async path => {
      downloads++; await writeFile(path, scenario === 'untrusted download' ? 'wrong' : bytes);
    } };
    try {
      if (scenario === 'untrusted download') {
        await assert.rejects(materializePackage(options), /SHA256 mismatch/);
        await assert.rejects(readFile(cacheFile), { code: 'ENOENT' });
        await assert.rejects(readFile(outputFile), { code: 'ENOENT' });
      } else {
        await materializePackage(options);
        await rm(join(root, 'build'), { recursive: true });
        if (scenario === 'corrupted cache') await writeFile(cacheFile, 'corrupted');
        const result = await materializePackage(options);
        assert.deepEqual(await readFile(outputFile), bytes);
        assert.equal(downloads, scenario === 'corrupted cache' ? 2 : 1);
        assert.equal(result.cacheHit, scenario !== 'corrupted cache');
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}
