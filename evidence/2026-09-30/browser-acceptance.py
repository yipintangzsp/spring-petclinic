from pathlib import Path
from playwright.sync_api import sync_playwright,expect
import json,sys
base=sys.argv[1];phase=sys.argv[2]
out=Path(__file__).resolve().parent
results=[]
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',args=['--no-proxy-server','--host-resolver-rules=MAP petclinic.devops.local 192.168.1.58'])
 for size,viewport in [('desktop',{'width':1440,'height':1000}),('mobile',{'width':390,'height':844})]:
  page=b.new_page(viewport=viewport); errors=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  for name,path in [('home','/'),('owners','/owners'),('owner','/owners/1'),('pet','/owners/1/pets/1'),('pets','/pets'),('visit','/owners/1/pets/1/visits/new'),('vets','/vets.html'),('status','/system-status')]:
   res=page.goto(base+path,timeout=45000);page.wait_for_load_state('networkidle');page.wait_for_function("document.getAnimations().every(a => a.playState === 'finished')");assert res.status==200,(path,res.status)
   assert '??clinic.' not in page.content(),path
   overflow=page.evaluate('document.documentElement.scrollWidth > innerWidth')
   assert not overflow,(path,size,'horizontal overflow')
   page.screenshot(path=str(out/f'{phase}-{name}-{size}.png'),full_page=True)
   results.append({'size':size,'page':path,'status':res.status,'overflow':overflow});print(size,path,'PASS',flush=True)
  page.goto(base+'/owners');page.get_by_label('Owner name or telephone').fill('George');page.get_by_role('button',name='Apply filters').click();expect(page.get_by_role('link',name='George Franklin')).to_be_visible();page.get_by_role('link',name='George Franklin').click();page.get_by_role('link',name='Pet details & all visits').click();expect(page.get_by_role('heading',name='Leo',exact=True)).to_be_visible()
  page.get_by_role('link',name='Add visit',exact=True).click();page.get_by_label('Visit date').fill('');page.get_by_role('button',name='Save visit').click();assert page.locator('#date').evaluate('(e)=>!e.checkValidity()');expect(page.get_by_role('heading',name='New visit for Leo')).to_be_visible()
  page.goto(base+'/owners');page.get_by_label('Owner name or telephone').fill('not-a-real-owner');page.get_by_role('button',name='Apply filters').click();expect(page.get_by_role('heading',name='No owners found')).to_be_visible()
  page.goto(base+'/pets');page.get_by_label('Pet type').select_option('cat');page.get_by_role('button',name='Apply filters').click();assert 'type=cat' in page.url
  page.goto(base+'/vets.html');page.get_by_label('Specialty').select_option('radiology');page.get_by_role('button',name='Apply filters').click();expect(page.get_by_role('heading',name='Helen Leary')).to_be_visible();expect(page.get_by_role('heading',name='James Carter')).to_have_count(0)
  if size=='mobile':
   page.get_by_role('button',name='Toggle navigation').click() if page.get_by_role('button',name='Toggle navigation').count() else page.locator('.navbar-toggler').click()
   expect(page.locator('#main-navbar')).to_be_visible()
  assert not errors,errors
  results.append({'size':size,'flows':'PASS','javascript_errors':errors});page.close()
 b.close()
(out/f'{phase}-browser-results.json').write_text(json.dumps(results,indent=2))
