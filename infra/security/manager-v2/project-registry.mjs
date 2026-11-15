// Single source of truth for Manager project definitions (T06 unification).
// Merges the SBOM project registry and the CI project registry exactly as
// view/controls.mjs historically did on its own: SBOM definitions first, CI
// definitions win on key collision. Read fresh on every call, as before.
import fs from 'node:fs';
export function sbomProjectDefinitions(){return JSON.parse(fs.readFileSync(new URL('./sbom/projects.json',import.meta.url))).projects;}
export function ciProjects(){return JSON.parse(fs.readFileSync(new URL('./ci/projects.json',import.meta.url)));}
export function projectDefinitions(){return {...sbomProjectDefinitions(),...ciProjects()};}
export function knownProject(projectId){return Object.hasOwn(projectDefinitions(),projectId);}
