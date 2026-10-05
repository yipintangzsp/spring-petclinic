// Uses the bundled Playwright runtime; only synthetic acceptance records are created.
const {chromium}=require('playwright');const fs=require('fs');
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',args:['--no-proxy-server','--host-resolver-rules=MAP petclinic.devops.local 192.168.1.58']});
 const p=await b.newPage();const out={pages:[],errors:[]};p.on('pageerror',e=>out.errors.push(String(e)));
 const base='http://petclinic.devops.local';
 async function go(path){let t=Date.now(),r=await p.goto(base+path,{timeout:45000});await p.waitForLoadState('networkidle');out.pages.push({path,status:r.status(),milliseconds:Date.now()-t});if(r.status()!=200)throw Error(path+' status '+r.status());}
 try{
 for(const path of ['/','/owners?q=Demo&page=1','/owners?q=Demo&page=2','/owners?q=Demo&city=DemoDistrict1','/owners/1000001','/owners/1000001/pets/1000001','/pets','/vets.html','/system-status'])await go(path);
 await go('/owners/new');out.ownerInputs=await p.locator('input').evaluateAll(es=>es.map(e=>({id:e.id,name:e.name,type:e.type})));
 for(const [id,v]of Object.entries({firstName:'DemoAcceptance',lastName:'Capacity20261006',address:'Synthetic acceptance street',city:'DemoAcceptance',telephone:'5550199999'}))await p.locator('#'+id).fill(v);
 await p.locator('form button[type=submit]').click();await p.waitForURL(/\/owners\/\d+$/);out.ownerId=Number(p.url().split('/').pop());
 await go('/owners/'+out.ownerId+'/edit');await p.locator('#city').fill('DemoAcceptanceUpdated');await p.locator('form button[type=submit]').click();await p.waitForURL(base+'/owners/'+out.ownerId);if(!(await p.locator('body').innerText()).includes('DemoAcceptanceUpdated'))throw Error('owner update missing');out.update=true;
 await go('/owners/'+out.ownerId+'/pets/new');out.petInputs=await p.locator('input,select').evaluateAll(es=>es.map(e=>({id:e.id,name:e.name,type:e.type,options:e.options?Array.from(e.options).map(o=>({value:o.value,text:o.text})):undefined})));
 await p.locator('#name').fill('DemoAcceptancePet');await p.locator('#birthDate').fill('2022-01-01');await p.locator('select[name=type]').selectOption({label:'cat'});await p.locator('form button[type=submit]').click();await p.waitForURL(base+'/owners/'+out.ownerId);
 const petLink=await p.locator('a[href*="/pets/"]').evaluateAll(es=>es.map(e=>e.getAttribute('href')).filter(v=>/\/pets\/\d+$/.test(v)));if(!petLink.length)throw Error('pet link absent');out.petId=Number(petLink[0].split('/').pop());
 await go('/owners/'+out.ownerId+'/pets/'+out.petId+'/edit');await p.locator('#name').fill('DemoAcceptancePetUpdated');await p.locator('form button[type=submit]').click();await p.waitForURL(base+'/owners/'+out.ownerId);
 await go('/owners/'+out.ownerId+'/pets/'+out.petId+'/visits/new');out.visitInputs=await p.locator('input,textarea').evaluateAll(es=>es.map(e=>({id:e.id,name:e.name,type:e.type})));
 await p.locator('#date').fill('2026-10-08');await p.locator('[name=description]').fill('Synthetic capacity acceptance appointment');await p.locator('form button[type=submit]').click();await p.waitForURL(/\/pets\/\d+/);if(!(await p.locator('body').innerText()).includes('Synthetic capacity acceptance appointment'))throw Error('visit missing');out.visit=true;
 await go('/owners?q=DemoAcceptance');if(!(await p.locator('body').innerText()).includes('Capacity20261006'))throw Error('search missing');out.search=true;out.result='PASS';
 }catch(e){out.result='FAIL';out.failure=String(e);}
 finally{fs.writeFileSync(process.argv[2],JSON.stringify(out,null,2));await b.close();console.log(JSON.stringify(out));}
 if(out.result!='PASS')process.exitCode=1;
})();
