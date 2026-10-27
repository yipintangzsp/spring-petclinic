import test from 'node:test';
import assert from 'node:assert/strict';
import {harborZone,foreignZones} from './registry-dns.mjs';
test('Harbor zone targets only a valid existing service IPv4 without accepting configuration injection',()=>{
 assert.match(harborZone('10.43.28.42'),/10\.43\.28\.42 core\.harbor\.domain/);
 for(const ip of ['None','10.43.28.42\nforward . attacker','::1','hostname'])assert.throws(()=>harborZone(ip));
});
test('shared CoreDNS zones are retained and compared independently of the owned Harbor key',()=>{
 const before={'github.server':'existing-github','forward.override':'existing-upstream'};
 assert.deepEqual(foreignZones({...before,'platform-harbor.server':harborZone('10.43.28.42')}),before);
 assert.notDeepEqual(foreignZones({...before,'github.server':'changed'}),before);
});
