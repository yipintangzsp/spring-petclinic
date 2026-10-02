from pathlib import Path
import sys,json
from playwright.sync_api import sync_playwright
base=sys.argv[1];phase=sys.argv[2];out=Path(__file__).resolve().parent
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',args=['--no-proxy-server','--host-resolver-rules=MAP petclinic.devops.local 192.168.1.58'])
 result=[]
 for size,viewport in [('desktop',{'width':1440,'height':1000}),('mobile',{'width':390,'height':844})]:
  page=browser.new_page(viewport=viewport);errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  for route in ['/','/system-status','/platform']:
   response=page.goto(base+route,timeout=45000);page.wait_for_load_state('networkidle');assert response.status==200
   assert '??clinic.' not in page.content()
   assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
   if route=='/platform':
    assert page.locator('tbody tr').count()>=74
    assert page.locator('.platform-links a[href^="//grafana"]').count()==1
    assert page.locator('.platform-links a[href^="//kibana"]').count()==1
    assert page.locator('tbody').inner_text().find('sonarqube')>=0
    page.screenshot(path=str(out/f'{phase}-platform-{size}.png'),full_page=True)
   result.append({'size':size,'route':route,'status':200,'overflow':False})
  assert not errors;page.close()
 browser.close();(out/f'{phase}-browser.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
