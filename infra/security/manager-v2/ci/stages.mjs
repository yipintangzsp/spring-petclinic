// Bounded local execution evidence. No raw error text, command arguments or findings.
import fs from 'node:fs';
const allowed=new Set(['SOURCE_READY','SCANNER_START_ATTEMPT','SCANNER_STARTED','SCANNER_EXITED','RESULT_VALIDATED','RUN_COMPLETED','RUN_FAILED']);
export function stageWriter(file,runId){
 if(!/^web-[a-f0-9-]{36}$/.test(runId))throw Error('STAGE_RUN_ID');
 return(stage,details={})=>{if(!allowed.has(stage)||Object.keys(details).some(k=>!['exitCode','errorCategory','summary','pid'].includes(k)))throw Error('STAGE_FIELDS');const row={runId,stage,time:new Date().toISOString(),exitCode:null,errorCategory:null,summary:null,...details};if(row.errorCategory&&!/^[A-Z_]+$/.test(row.errorCategory)||row.summary&&!/^[a-zA-Z0-9 _.,:-]{1,160}$/.test(row.summary))throw Error('STAGE_REDACTION');const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_APPEND|fs.constants.O_CREAT|fs.constants.O_NOFOLLOW,0o600);try{fs.writeSync(fd,JSON.stringify(row)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}};
}
