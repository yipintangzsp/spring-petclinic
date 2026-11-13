import {highAlerts} from './gate-contract.mjs';
const categories=new Set(['sql_injection','command_injection','xss','path_traversal','ssrf','auth_bypass']);
const ordinary=new Set(['10020','10021','10038','10062']);
export function classifyZap(data,context,approved){
 highAlerts(data);if(approved?.schema!==1||!Array.isArray(approved.confirmations))throw Error('Invalid reviewed DAST confirmations');
 const alerts=data.site.flatMap(s=>s.alerts??[]),blocking=[],warnings=[];
 for(const a of alerts){
  const proof=approved.confirmations.find(p=>String(p.pluginid)===String(a.pluginid)&&p.targetImage===context.targetImage&&p.reportSha256===context.reportSha256&&Array.isArray(a.instances)&&a.instances.some(i=>i.uri===p.uri&&i.method==='GET'));
  const verified=Number(a.riskcode)===3&&!ordinary.has(String(a.pluginid))&&proof&&categories.has(proof.category)&&proof.positiveValidated===true&&proof.negativeValidated===true&&proof.exploitConfirmed===true&&proof.evidenceVerified===true&&typeof proof.evidencePath==='string'&&proof.evidencePath.length>0&&Number.isFinite(Date.parse(proof.expiresAt))&&Date.parse(proof.expiresAt)>Date.now();
  if(verified)blocking.push({...a,confirmation:proof});else warnings.push({...a,gateReason:Number(a.riskcode)===3?'High lacks reviewed exact-target exploit confirmation or is ordinary information':'Medium/Low/Informational remains WARN'});
 }
 return {blocking,warnings,rawHigh:alerts.filter(a=>Number(a.riskcode)===3).length,unconfirmedHigh:warnings.filter(a=>Number(a.riskcode)===3).length,scope:'Passive fixed GET only; empty/clean alerts do not prove absence of injection or authentication flaws'};
}
