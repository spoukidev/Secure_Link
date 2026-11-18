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

test('ordinary domains ending in "t.co…" are not treated as link shorteners', () => {
  for (const url of ['https://www.microsoft.com/en-us/security', 'https://att.com/support']) {
    assert.ok(!analyze(url).signs.includes('Shortened link hides its destination'), url);
  }
});

test('real shortener hosts are still flagged', () => {
  for (const url of ['http://bit.ly/abc', 'https://t.co/xyz', 'https://tinyurl.com/x', 'www.cutt.ly/y']) {
    assert.ok(analyze(url).signs.includes('Shortened link hides its destination'), url);
  }
});

test('keywords inside other words do not trigger rules', () => {
  assert.deepEqual(analyze('Thanks for the invite to dinner').signs, []);
  assert.deepEqual(analyze('I can repay you next week').signs, []);
  assert.deepEqual(analyze('Lovely visage in that portrait').signs, []);
});

test('keyword plurals and French/Arabic terms still match', () => {
  assert.ok(analyze('Claim your prizes now').signs.includes('Unexpected prize or giveaway'));
  assert.ok(analyze('Vous avez gagné un cadeau').signs.includes('Unexpected prize or giveaway'));
  assert.ok(analyze('Répondez vite').signs.includes('Pressure or urgent language'));
  assert.ok(analyze('ربحت هدية').signs.includes('Unexpected prize or giveaway'));
  assert.ok(analyze('Pay 150 DA now to release your parcel.').signs.includes('Requests money or payment'));
});

test('punctuation after a link does not hide its domain', () => {
  for (const text of ['Pay here: http://baridimob-support.top.', 'Login (https://edahabia-pay.xyz)', 'Open https://evil.click/a.exe!']) {
    const r = analyze(text);
    assert.ok(r.signs.includes('Unusual or dangerous domain/file type'), text);
    assert.ok(!/[.)!]$/.test(r.links[0]), r.links[0]);
  }
});

test('bare domains without http or www are analyzed as links', () => {
  const r = analyze('Votre colis est bloqué, payez 150 DA sur algerie-poste.top/pay');
  assert.deepEqual(r.links, ['algerie-poste.top/pay']);
  assert.ok(r.signs.includes('Unusual or dangerous domain/file type'));
  assert.ok(r.signs.includes('Domain may imitate a known organization'));
  assert.ok(analyze('Claim it: bit.ly/3xYz').signs.includes('Shortened link hides its destination'));
});

test('e-mail addresses, file names and plain prose are not read as bare links', () => {
  assert.deepEqual(analyze('Write to support@example.com please').links, []);
  assert.deepEqual(analyze('I attached holiday.mov and photos.zip').links, []);
  assert.deepEqual(analyze('See you at 5. Thanks, ok.').links, []);
  assert.equal(analyze('Read the docs at example.com/help').level, 'Safe');
});
