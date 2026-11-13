import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'sonar-policy'))
from collect import call
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
 def b=Jenkins.instance.getItemByFullName('petclinic-ci').getBuildByNumber(270)
 def names=['attestation-envelope.json','attestation-verification.json','provenance.json','build-attestation-envelope.json','build-attestation-verification.json','runtime-baseline.json','runtime-health.json','sbom-summary.json','secrets-gate.json','signing-admission.json','admission-gate.json','kyverno-rbac.json','defectdojo-import.json','kubescape-gate.json','command-audit.json']
 def reports=[:];def missing=[]
 for(name in names){def f=b.artifactManager.root().child('.devsecops/'+name);if(!f.exists()){missing<<name;continue};def s=f.open().getText('UTF-8');assert s.length()<4000000:'Bounded evidence limit';reports[name]=new JsonSlurper().parseText(s)}
 println(JsonOutput.toJson([job:b.parent.fullName,build:b.number,result:b.result.toString(),reports:reports,missing:missing]))
'''
x=call(script,'remaining-source-270.json')
# call writes in sonar directory by existing helper; retain original and create this scope's copy.
(Path(__file__).parent/'archived-270.json').write_text(json.dumps(x,indent=2))
print(json.dumps({'build':x['build'],'available':list(x['reports']),'missing':x['missing']},indent=2))
