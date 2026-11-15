import fs from 'node:fs';
import {guard} from './recorder.mjs';

// Runtime collector for the defectdojo source (governance/defectdojo.mjs).
// Mirrors the frozen shape policy/dojo-parent.mjs replays through
// policy/dojo-frozen-io.mjs: input file contents, the target, credential
// PRESENCE only, and the API observations (test list, findings per test,
// product findings, Sonar export) needed for the frozen client to re-derive
// the same imports and counts. API tokens are never recorded; request
// bodies (uploaded scan reports) are not recorded either — the frozen
// replay re-reads them from the recorded input files.
export function createDojoCollector() {
  const apiLog = [];
  const raw = {files:{},api:{},credentials:{},tests:[],findingsByTest:{}};
  return {raw,apiLog,
    credentials() { raw.credentials = {dojo:!!process.env.DEFECTDOJO_TOKEN,sonar:!!process.env.SONAR_TOKEN}; },
    target(t) { raw.target = t; },
    build() { raw.build = process.env.BUILD_NUMBER; },
    recordFiles(paths) {
      for (const p of paths) guard(() => { raw.files[p] = fs.readFileSync(p,'utf8'); });
    },
    sonar(body) { raw.sonar = body; },
    // A fetch implementation for DojoClient that performs the real request
    // unchanged and records the response (status + parsed body) in order.
    wrapFetch(realFetch = globalThis.fetch) {
      return async (url,options = {}) => {
        const r = await realFetch(url,options);
        let body = null;
        try { body = await r.clone().json(); } catch { body = null; }
        apiLog.push({method:options.method ?? 'GET',url:String(url),status:r.status,body});
        return r;
      };
    },
    // Translate the ordered API log into the frozen replay slots. The
    // frozen client starts from raw.tests and matches by title, then
    // queries findings by the matched (production) id — so raw.tests
    // must be ONE consistent snapshot carrying production ids: the LAST
    // complete tests-list sequence (pages concatenated, a new sequence
    // starts at a URL without offset). Findings per test keep the LAST
    // observation (post-reimport state); product findings concatenate
    // the pages of their single list call in order.
    finish() {
      let tests = null, current = null, product = null;
      for (const e of apiLog) {
        if (e.method !== 'GET' || !e.body) continue;
        let u; try { u = new URL(e.url); } catch { continue; }
        if (u.pathname === '/api/v2/tests/') {
          const offset = u.searchParams.get('offset');
          if (offset === null || offset === '0') current = [];
          if (current) current.push(...(e.body.results ?? []));
          tests = current;
        }
        else if (u.pathname === '/api/v2/findings/' && u.searchParams.has('test')) raw.findingsByTest[u.searchParams.get('test')] = e.body.results ?? [];
        else if (u.pathname === '/api/v2/findings/' && u.searchParams.has('test__engagement__product')) product = [...(product ?? []),...(e.body.results ?? [])];
      }
      if (tests) { const seen = new Set(); raw.tests = tests.filter(t => !seen.has(t.id) && seen.add(t.id)); }
      if (product) raw.productFindings = product;
      return raw;
    }
  };
}
