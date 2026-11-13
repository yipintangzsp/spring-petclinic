// Authorized existing credentials, read-only capability discovery. Never writes.
import fs from 'node:fs';import {sha} from '../summary-v2/codec.mjs';
const out='.devsecops/runtime-controlled/build-'+process.env.BUILD_NUMBER;fs.mkdirSync(out,{recursive:true});
const rows=[];async function get(system,base,p,auth){const r=await fetch(base+p,{method:'GET',headers:{Authorization:auth},signal:AbortSignal.timeout(15000)});let body;try{body=await r.json();}catch{}rows.push({system,method:'GET',path:p,httpStatus:r.status});return {status:r.status,body};}
const report={scope:'LIVE_READ_ONLY',validationRunId:JSON.parse(fs.readFileSync('runtime-validation-run.json')).validationRunId,externalWriteCount:0};
if(!process.env.HARBOR_USER||!process.env.HARBOR_PASS||!process.env.DEFECTDOJO_TOKEN)throw Error('Explicit authorized existing identities absent; no fallback');
const hb='http://harbor-core.harbor.svc.cluster.local',ha='Basic '+Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64');
const user=await get('Harbor',hb,'/api/v2.0/users/current',ha),project=await get('Harbor',hb,'/api/v2.0/projects/petclinic',ha);
report.harbor={currentUserHttpStatus:user.status,identity:user.status===200?{username:user.body.username,sysadminFlag:user.body.sysadmin_flag}:null,project:project.status===200?{id:project.body.project_id,name:project.body.name}:null,validationCandidate:'NOT_ESTABLISHED',candidateCleanupAuthorization:'NOT_ESTABLISHED'};
if(project.status===200){const rules=await get('Harbor',hb,'/api/v2.0/projects/'+project.body.project_id+'/immutabletagrules',ha);report.harbor.immutableRules={httpStatus:rules.status,count:Array.isArray(rules.body)?rules.body.length:null,rulesSha256:rules.body?sha(JSON.stringify(rules.body)):null};}
const target=JSON.parse(fs.readFileSync('infra/security/governance/dojo-target.json')),da='Token '+process.env.DEFECTDOJO_TOKEN;
const products=await get('DefectDojo',target.baseUrl,'/api/v2/products/?limit=100',da),engagements=await get('DefectDojo',target.baseUrl,'/api/v2/engagements/?limit=100',da);
const minimal=x=>(x?.results??[]).map(r=>({id:r.id,name:r.name,product:r.product??null}));
report.defectdojo={configuredTarget:{baseUrl:target.baseUrl,product:target.product,engagement:target.engagement},visibleProducts:minimal(products.body),visibleEngagements:minimal(engagements.body),productListHttpStatus:products.status,engagementListHttpStatus:engagements.status,cleanupAuthorization:'NOT_ESTABLISHED_NO_WRITE_PROBE',realIsolatedParentAvailable:false};
report.requests=rows;fs.writeFileSync(out+'/readonly-boundary-discovery.json',JSON.stringify(report,null,2));console.log(JSON.stringify({readOnlyRequests:rows.length,externalWriteCount:0,report:out+'/readonly-boundary-discovery.json'}));
