import test from 'node:test';
import assert from 'node:assert/strict';
import {localHost,localOrigin} from './origins.mjs';
test('exact security domain with port accepted',()=>{assert.equal(localHost('security.devops.local:17862'),true);assert.equal(localOrigin('http://security.devops.local:17862'),true);});
test('other local names not blanket trusted',()=>{for(const h of ['security.devops.local.evil:17862','evil.devops.local:17862','security.devops.local','0.0.0.0:17862','192.168.1.58:17862'])assert.equal(localHost(h),false);});
test('scheme userinfo and origin injection rejected',()=>{for(const o of ['https://security.devops.local:17862','http://security.devops.local:17862.evil','http://security.devops.local:17862@evil','null'])assert.equal(localOrigin(o),false);});
