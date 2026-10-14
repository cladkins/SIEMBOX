import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commonNames, normalizeTlsSubject } from './tlsSubject';

test('commonNames reads a single-string CN (the shape stored before multi-CN support)', () => {
  assert.deepEqual(commonNames('pve'), ['pve']);
});

test('commonNames reads every CN of a repeated-CN array, in order', () => {
  assert.deepEqual(commonNames(['proxmox.local', 'pve']), ['proxmox.local', 'pve']);
});

test('commonNames ignores missing, empty and non-string values instead of throwing', () => {
  assert.deepEqual(commonNames(undefined), []);
  assert.deepEqual(commonNames(null), []);
  assert.deepEqual(commonNames(''), []);
  assert.deepEqual(commonNames(42), []);
  assert.deepEqual(commonNames({ CN: 'pve' }), []);
  assert.deepEqual(commonNames(['pve', 7, null, '', 'proxmox.local']), ['pve', 'proxmox.local']);
});

test('normalizeTlsSubject keeps a single CN as a string, so stored evidence is unchanged for it', () => {
  assert.deepEqual(normalizeTlsSubject({ port: 8006, subject_cn: 'pve', san: ['DNS:pve'] }), {
    port: 8006,
    subject_cn: 'pve',
    san: ['DNS:pve'],
  });
});

test('normalizeTlsSubject keeps several CNs as an array', () => {
  assert.deepEqual(normalizeTlsSubject({ port: 8006, subject_cn: ['proxmox.local', 'pve'] }), {
    port: 8006,
    subject_cn: ['proxmox.local', 'pve'],
  });
});

test('normalizeTlsSubject collapses an array left with one usable CN to a string, and drops an unusable CN', () => {
  assert.deepEqual(normalizeTlsSubject({ port: 443, subject_cn: ['pve', 5] }), { port: 443, subject_cn: 'pve' });
  assert.deepEqual(normalizeTlsSubject({ port: 443, subject_cn: 5 }), { port: 443 });
  assert.deepEqual(normalizeTlsSubject({ port: 443 }), { port: 443 });
});

test('normalizeTlsSubject drops non-string SAN entries and entries without an integer port', () => {
  assert.deepEqual(normalizeTlsSubject({ port: 443, san: ['DNS:a', 1, null] }), { port: 443, san: ['DNS:a'] });
  assert.equal(normalizeTlsSubject({ subject_cn: 'pve' }), null);
  assert.equal(normalizeTlsSubject({ port: '443', subject_cn: 'pve' }), null);
  assert.equal(normalizeTlsSubject(null), null);
  assert.equal(normalizeTlsSubject('pve'), null);
});
