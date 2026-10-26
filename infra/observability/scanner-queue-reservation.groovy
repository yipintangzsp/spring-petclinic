import jenkins.model.Jenkins
import hudson.model.Queue
import hudson.model.Run
import hudson.model.queue.QueueTaskDispatcher
import hudson.model.queue.CauseOfBlockage
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.util.concurrent.Callable

// Temporary queue veto. Does not set Jenkins shutdown/quiet mode or modify jobs.
class PlatformScannerQueueReservation extends QueueTaskDispatcher {
 String reservationHolder
 String currentJob
 int currentBuild
 CauseOfBlockage canRun(Queue.Item item) {
  def owner=item.task.getOwnerExecutable()
  if(owner instanceof Run && owner.parent.fullName==currentJob && owner.number==currentBuild)return null
  final String description='Scanner memory reserved by '+reservationHolder
  return new CauseOfBlockage(){String getShortDescription(){return description}}
 }
}
def input=new JsonSlurper().parseText(new String('INPUT_BASE64'.decodeBase64(),'UTF-8'))
assert input.holder==~ /jenkins-petclinic-[0-9]+|ci-scanner-slot-proof[^ ]*/
assert input.job=='petclinic-ci'
assert input.mode in ['reserve','status','release']
def result=Queue.withLock({
 def list=QueueTaskDispatcher.all()
 def ours=list.findAll{it.class.name=='PlatformScannerQueueReservation'}
 assert ours.size()<=1
 if(ours)assert ours[0].reservationHolder==input.holder : 'Foreign queue reservation preserved'
 if(input.mode=='reserve'){
  assert !Jenkins.instance.quietingDown : 'Do not borrow global shutdown mode'
  def other=Jenkins.instance.getAllItems(hudson.model.Job).findAll{j->j.builds.any{b->b.building && !(j.fullName==input.job && b.number==input.build)}}
  assert other.empty : 'Other running builds prevent idle scanner reservation'
  if(!ours){list.add(new PlatformScannerQueueReservation(reservationHolder:input.holder,currentJob:input.job,currentBuild:input.build as int))}
 }else if(input.mode=='release' && ours){assert list.remove(ours[0])}
 def current=list.findAll{it.class.name=='PlatformScannerQueueReservation'}
 return [holder:input.holder,reserved:!current.empty,quietingDown:Jenkins.instance.quietingDown,queuedItems:Jenkins.instance.queue.items.size(),mode:input.mode]
} as Callable)
Jenkins.instance.queue.scheduleMaintenance()
println('SCANNER_QUEUE_JSON '+JsonOutput.toJson(result))
