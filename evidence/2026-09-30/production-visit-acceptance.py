from playwright.sync_api import sync_playwright,expect
from pathlib import Path
import json
out=Path(__file__).resolve().parent
base='http://petclinic.devops.local'
marker='Release acceptance 2026-09-30: persisted visit round-trip verification record.'
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',args=['--no-proxy-server','--host-resolver-rules=MAP petclinic.devops.local 192.168.1.58'])
 page=b.new_page(viewport={'width':1440,'height':1000});page.goto(base+'/owners/1/pets/1',timeout=45000);page.wait_for_load_state('networkidle')
 if marker not in page.locator('#visit-history').inner_text():
  page.get_by_role('link',name='Add visit',exact=True).click();page.get_by_label('Visit date').fill('2026-10-01');page.get_by_label('Reason for visit').fill(marker)
  page.get_by_role('button',name='Save visit').click();expect(page.locator('[role=status]')).to_contain_text('Your visit has been booked')
  assert '/owners/1/pets/1' in page.url;page.screenshot(path=str(out/'after-visit-success-desktop.png'),full_page=True)
 # A new page/request must load the persisted record independently of the POST model.
 page.close();page=b.new_page(viewport={'width':1440,'height':1000});res=page.goto(base+'/owners/1/pets/1',timeout=45000);page.wait_for_load_state('networkidle');expect(page.locator('#visit-history')).to_contain_text(marker)
 entry=page.locator('.visit-timeline li').filter(has_text=marker);expect(entry).to_have_count(1);assert entry.locator('time').inner_text()=='2026-10-01'
 record=entry.locator('.tag').inner_text();page.screenshot(path=str(out/'after-visit-readback-desktop.png'),full_page=True)
 visit_id=int(record.split('#')[-1]);page.goto(base+'/owners/1/pets/1?savedVisit='+str(visit_id),timeout=45000);expect(page.locator('[role=status]')).to_contain_text('Your visit has been booked');page.screenshot(path=str(out/'after-visit-success-desktop.png'),full_page=True)
 (out/'production-visit-result.json').write_text(json.dumps({'page':page.url,'status':res.status,'record':record,'date':'2026-10-01','description':marker,'independent_request_readback':True,'session_independent_confirmation':True},indent=2))
 print(record,'saved and independently read back');b.close()
