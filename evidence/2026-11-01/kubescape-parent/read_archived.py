import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'sonar-policy'));from collect import call
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.security.MessageDigest
 def b=Jenkins.instance.getItemByFullName('petclinic-ci').getBuildByNumber(270)
 def paths=['cluster-nsa','yaml-nsa','cluster-cis-v1.12.0','yaml-cis-v1.12.0'];def reports=[:]
 for(p in paths){def f=b.artifactManager.root().child('.devsecops/kubescape/'+p+'.json');assert f.exists():'Report unavailable: '+p
 def bytes=f.open().bytes;assert bytes.length<12000000:'Bounded report exceeded';def raw=new JsonSlurper().parseText(new String(bytes,'UTF-8'))
 // Only fields read by the unchanged summarizer; no resource specs/configuration values.
 def projected=[results:raw.results.collect{r->[resourceID:r.resourceID,controls:r.controls?.collect{c->[controlID:c.controlID,status:c.status,severity:c.severity]}]},resources:raw.resources.collect{[:]},summaryDetails:[controls:raw.summaryDetails.controls,complianceScore:raw.summaryDetails.complianceScore,resourcesSeverityCounters:raw.summaryDetails.resourcesSeverityCounters]]
 reports[p]=[originalSha256:MessageDigest.getInstance('SHA-256').digest(bytes).encodeHex().toString(),originalBytes:bytes.length,consumedFacts:projected]
 }
 println(JsonOutput.toJson([build:270,reports:reports,classification:'HISTORICAL_ARCHIVE_CONSUMED_FIELD_PROJECTION',omitted:'Resource specs/metadata and other unused fields excluded; original remote reports untouched']))
'''
x=call(script,'kubescape-consumed-fields-270.json')
Path(__file__).with_name('archived-consumed-fields.json').write_text(json.dumps(x,indent=2));print('Read four archived native reports; consumed fields only.')
