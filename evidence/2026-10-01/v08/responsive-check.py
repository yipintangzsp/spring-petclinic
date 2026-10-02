from pathlib import Path
from playwright.sync_api import sync_playwright
import json,sys
base=sys.argv[1];out=Path(__file__).resolve().parent;records=[]
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',args=['--no-proxy-server','--host-resolver-rules=MAP petclinic.devops.local 192.168.1.58'])
 for width in (320,768,1024):
  page=b.new_page(viewport={'width':width,'height':900})
  for path in ('/','/owners','/pets','/owners/1/pets/1/visits/new','/system-status'):
   r=page.goto(base+path);page.wait_for_load_state('networkidle')
   assert r.status==200
   assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),(width,path)
   records.append({'width':width,'path':path,'overflow':False})
  page.close()
 page=b.new_page(viewport={'width':1440,'height':1000},reduced_motion='reduce');page.goto(base);page.wait_for_load_state('networkidle')
 assert page.locator('.landing-copy').evaluate("e=>getComputedStyle(e).animationName")=='none'
 page.keyboard.press('Tab');assert page.evaluate('document.activeElement.tagName')=='A'
 records.append({'reduced_motion':'PASS','keyboard_focus':'PASS'})
 b.close()
(out/'responsive-results.json').write_text(json.dumps(records,indent=2));print(json.dumps(records))
