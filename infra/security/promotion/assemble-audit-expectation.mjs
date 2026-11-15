// T07 C3 (G1): assemble BUILD_PROVENANCE_EXPECTATION for the audit Job from a
// candidate-build archived build-provenance.json, replacing hand-copied params.
// Usage: node assemble-audit-expectation.mjs <build-provenance.json>
// Output (stdout, JSON): {expectation:{commit,repository,builder,buildNumber}, candidateImage}
// The expectation key order matches Jenkinsfile.security-audit's required keySet:
// buildNumber, builder, commit, repository (order-insensitive set check upstream;
// emitted sorted for byte-stable diffs).
import fs from 'node:fs';

const path = process.argv[2];
if (!path) throw Error('usage: assemble-audit-expectation.mjs <build-provenance.json>');
const doc = JSON.parse(fs.readFileSync(path, 'utf8'));
const p = doc.predicate ?? doc;
const commit = p.source?.commit;
const repository = p.source?.repository;
const builder = p.builder?.identity;
const buildNumber = p.builder?.buildNumber;
const candidateImage = p.candidateImage;
if (!/^[a-f0-9]{40}$/.test(commit ?? '')) throw Error('predicate.source.commit missing or malformed');
if (!repository || !builder) throw Error('predicate source.repository or builder.identity missing');
if (!Number.isInteger(buildNumber) || buildNumber <= 0) throw Error('predicate.builder.buildNumber missing or malformed');
if (!/^.+@sha256:[a-f0-9]{64}$/.test(candidateImage ?? '')) throw Error('predicate.candidateImage missing or malformed');
if (p.compilation?.sourceCommit && p.compilation.sourceCommit !== commit) throw Error('predicate.compilation.sourceCommit disagrees with source.commit');
const expectation = { buildNumber, builder, commit, repository };
process.stdout.write(JSON.stringify({ expectation, candidateImage }) + '\n');
