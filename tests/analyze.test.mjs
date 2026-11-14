// Unit tests for the rule-based detector. Run with `npm test` (Node 22.18+ strips TS types natively).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../app/lib/analyze.ts';

test('bundled message example is Dangerous', () => {
  const r = analyze('URGENT: Your BaridiMob account will be suspended today. Verify your OTP and password now at http://baridimob-support.top/login');
  assert.equal(r.level, 'Dangerous');
  assert.ok(r.signs.includes('Requests sensitive security information'));
  assert.ok(r.signs.includes('Link does not use secure HTTPS'));
  assert.deepEqual(r.links, ['http://baridimob-support.top/login']);
});

test('raw IP link with executable is flagged', () => {
  const r = analyze('http://192.168.1.55/secure-login.exe');
  assert.ok(r.signs.includes('Link uses a raw IP address'));
  assert.ok(r.signs.includes('Unusual or dangerous domain/file type'));
});

test('URL words are not treated as message language', () => {
  const r = analyze('https://www.pinterest.com/pin/12345');
  assert.ok(!r.signs.includes('Requests sensitive security information'));
  assert.equal(r.level, 'Safe');
});

test('plain friendly message is Safe', () => {
  const r = analyze('Hi, are we still meeting for coffee on Saturday?');
  assert.equal(r.level, 'Safe');
  assert.deepEqual(r.signs, []);
});

test('score is capped at 100', () => {
  const r = analyze('URGENT!!! winner prize pay now OTP password police http://1.2.3.4/a.exe http://bit.ly/x http://baridi-x.top/');
  assert.equal(r.score, 100);
  assert.equal(r.level, 'Dangerous');
});
