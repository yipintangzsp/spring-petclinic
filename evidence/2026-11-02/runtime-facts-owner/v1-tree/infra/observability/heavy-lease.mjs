// Shared admission token for this release and controlled analysis runs.
import {spawnSync} from 'node:child_process';
const holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`;
if(!holder||holder.endsWith('undefined'))throw Error('Explicit heavy-task holder required');
function kube(args,input){const r=spawnSync('kubectl',['--request-timeout=10s',...args],{input,encoding:'utf8',timeout:12000});return r;}
const name='platform-heavy',namespace='data-infra';
// Kubernetes MicroTime requires exactly six fractional digits.
const microTime=()=>new Date().toISOString().replace(/(\.\d{3})Z$/, '$1000Z');
if(process.argv[2]==='acquire'){
 const response=await fetch('http://10.43.111.46:9090/api/v1/query?query='+encodeURIComponent('node_memory_MemAvailable_bytes{instance="10.0.0.3:9100"}'),{signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Memory admission evidence unavailable');
 const series=(await response.json()).data?.result;
 if(series?.length!==1||Date.now()/1000-Number(series[0].value[0])>60)throw Error('Fresh devops memory measurement required');
 const available=Number(series[0].value[1]),reserve=1250*1024*1024,task=1800*1024*1024;
 if(available<reserve+task)throw Error(`Insufficient measured memory: ${Math.round(available/1048576)} MiB; require 3050 MiB`);
 const obj={apiVersion:'coordination.k8s.io/v1',kind:'Lease',metadata:{name,namespace,labels:{'app.kubernetes.io/part-of':'petclinic-platform'}},spec:{holderIdentity:holder,acquireTime:microTime(),renewTime:microTime(),leaseDurationSeconds:3600}};
 const created=kube(['create','-f','-'],JSON.stringify(obj));
 if(created.status!==0)throw Error('Heavy lease admission failed: '+created.stderr.trim());
 console.log(JSON.stringify({holder,availableMiB:Math.round(available/1048576),reservedMiB:1250,additionalBudgetMiB:1800}));
}else if(process.argv[2]==='release'){
 const read=kube(['-n',namespace,'get','lease',name,'-o','json']);
 if(read.status!==0){console.log('No owned heavy lease to release');process.exit(0);}
 const obj=JSON.parse(read.stdout);
 if(obj.spec.holderIdentity!==holder){console.log('Lease belongs to another task; preserved');process.exit(0);}
 // JSON patch tests the holder and UID before allowing this object's deletion.
 const tested=kube(['-n',namespace,'patch','lease',name,'--type=json','-p',JSON.stringify([{op:'test',path:'/metadata/uid',value:obj.metadata.uid},{op:'test',path:'/spec/holderIdentity',value:holder},{op:'add',path:'/metadata/annotations',value:{'petclinic.devops.local/released-by':holder}}])]);
 if(tested.status!==0)throw Error('Heavy lease changed; preserved');
 const removed=kube(['-n',namespace,'delete','lease',name,'--wait=false']);
 if(removed.status!==0)throw Error('Could not release owned heavy lease');
 console.log('Owned heavy lease released');
}else throw Error('Use acquire or release');
