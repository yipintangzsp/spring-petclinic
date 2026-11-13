import test from 'node:test';
import assert from 'node:assert/strict';
import {reservationInput} from './scanner-queue-reservation.mjs';
test('queue reservation accepts only explicit scoped owner and build',()=>{
 assert.deepEqual(reservationInput('reserve','jenkins-petclinic-212','petclinic-ci','212'),{mode:'reserve',holder:'jenkins-petclinic-212',job:'petclinic-ci',build:212});
 for(const a of [['reserve','foreign','petclinic-ci',212],['bad','jenkins-petclinic-212','petclinic-ci',212],['release','jenkins-petclinic-212','other',212],['release','jenkins-petclinic-212','petclinic-ci','undefined']])assert.throws(()=>reservationInput(...a));
});
