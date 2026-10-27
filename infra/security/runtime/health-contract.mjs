export function validatePriorExit(current){
 if(!Number.isSafeInteger(current.restarts)||current.restarts<0)throw Error('Known Falco restart count required');
 if(!current.ready||!current.runningSince)throw Error('Falco must be Ready and running');
 if(current.restarts>0&&(current.priorExit?.exitCode!==0||current.priorExit?.reason!=='Completed'))throw Error('Non-clean historical Falco exit requires review');
}
export function validateRuntimeContinuity(current,baseline){
 for(const key of ['podUid','nodeBootId','containerId','runningSince','image','restarts'])if(current[key]!==baseline[key])throw Error('Falco changed during this build: '+key);
 if(!current.ready)throw Error('Falco readiness lost during build');
}
export function driverDiagnostics(log){
 const operational=log.split(/\r?\n/).filter(line=>{try{return !JSON.parse(line).rule;}catch{return true;}});
 const fatal=operational.filter(line=>/\b(?:fatal|panic)\b|(?:fail(?:ed|ure)?|error).*(?:load|attach).*(?:bpf|probe)|(?:bpf|probe).*(?:load|attach).*(?:fail(?:ed|ure)?|error)|error (?:loading|parsing).*rules?/i.test(line));
 return {fatalDriverLines:fatal.length,procFdWarnings:operational.filter(line=>line.includes('Unable to determine path for file descriptor')).length};
}
