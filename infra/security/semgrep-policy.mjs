export const enforcedRules=['java-weak-cipher','java-http-runtime-exec','java-http-process-builder'];
export function classifySemgrep(findings){
 const blocking=[],warnings=[];
 for(const f of findings){const id=f.check_id??f.rule_id;const severity=String(f.extra?.severity??f.severity??'').toUpperCase();
 (enforcedRules.includes(id)&&['ERROR','HIGH','CRITICAL'].includes(severity)?blocking:warnings).push(f);}
 return {blocking,warnings};
}
