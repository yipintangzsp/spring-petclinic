"""Read only archived public signatures, exact metadata hash and completed Gate nodes."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import java.security.MessageDigest
import org.jenkinsci.plugins.workflow.graph.FlowGraphWalker
import org.jenkinsci.plugins.workflow.actions.LabelAction
import org.jenkinsci.plugins.workflow.actions.ErrorAction
import org.jenkinsci.plugins.workflow.graph.BlockEndNode
def b=j.getBuildByNumber(270)
def c=Jenkins.instance.getItemByFullName('petclinic-candidate-build').getBuildByNumber(2)
def paths=['.devsecops/build-attestation-envelope.json','.devsecops/attestation-envelope.json']
def proof=paths.collectEntries{n->
 def f=new File(b.artifactsDir,n);assert f.length()<131072 && f.isFile()
 [(n):f.bytes.encodeBase64().toString()]
}
def cm=new File(c.artifactsDir,'target/platform/image-build-metadata.json');assert cm.length()<131072
String metadataHash=MessageDigest.getInstance('SHA-256').digest(cm.bytes).encodeHex().toString()
def nodes=new FlowGraphWalker(b.execution).collect{it}
def starts=nodes.findAll{it.getAction(LabelAction)?.displayName=='Security Gate'}
assert starts.size()==1
def start=starts.first()
def ends=nodes.findAll{it instanceof BlockEndNode && it.startNode.id==start.id}
assert ends.size()==1
println(JsonOutput.toJson([build:270,files:proof,metadataSha256:metadataHash,
 gateStage:[name:'Security Gate',startNode:start.id,endNode:ends.first().id,completed:true,
 errorOnStart:start.getAction(ErrorAction)!=null,errorOnEnd:ends.first().getAction(ErrorAction)!=null],
 totalErrorNodes:nodes.count{it.getAction(ErrorAction)!=null},latestProductionBuild:j.lastBuild.number]))
'''
r=p['script'](code)
with (OUT/'archived-proof.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps({k:v for k,v in r.items() if k!='files'}))
