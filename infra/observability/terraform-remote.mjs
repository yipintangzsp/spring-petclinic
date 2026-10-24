import {fileURLToPath} from 'node:url';
import path from 'node:path';
export {inspectRemotePlan,validateBootstrap} from './terraform-policy.mjs';
export async function run(){throw Error('Legacy in-Jenkins Terraform execution disabled; use isolated Jobs');}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))run().catch(e=>{console.error(e.message);process.exitCode=1;});
