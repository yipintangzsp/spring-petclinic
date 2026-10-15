// A cache hit is trusted only after checking the currently reviewed SHA256.
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export async function materializePackage({ sha256, cacheFile, outputFile, download }) {
  let bytes;
  try { bytes = await readFile(cacheFile); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const hit = bytes !== undefined && digest(bytes) === sha256;
  if (!hit) {
    await mkdir(dirname(cacheFile), { recursive: true, mode: 0o700 });
    const partial = `${cacheFile}.part-${process.pid}`;
    try {
      await download(partial);
      bytes = await readFile(partial);
      if (digest(bytes) !== sha256) throw new Error('Security package SHA256 mismatch');
      await writeFile(partial, bytes, { mode: 0o600 });
      await rename(partial, cacheFile);
    } finally { await rm(partial, { force: true }); }
  }
  await mkdir(dirname(outputFile), { recursive: true });
  const partial = `${outputFile}.part-${process.pid}`;
  try {
    await writeFile(partial, bytes);
    await rename(partial, outputFile);
  } finally { await rm(partial, { force: true }); }
  return { cacheHit: hit };
}
