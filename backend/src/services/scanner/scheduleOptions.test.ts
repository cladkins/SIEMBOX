/**
 * Scheduled-scan options per type: the shape check, what is still missing
 * before a schedule can run, and the targets each type names; plus the
 * dispatcher refusing a log discovery run that would sweep unconfirmed public
 * CIDRs. No database (the refused run never gets that far).
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { missingScanInputs, scanOptionsShapeError, scheduleTargets, templateSelectionError } from './scheduleOptions';
import { triggerScheduledScan } from '../../jobs/scheduledScans';
import type { ScheduledScan } from '../../models/ScheduledScan';

test('shape: every type, targets optional, malformed ones refused', () => {
  assert.equal(scanOptionsShapeError('asset', { scanType: 'ping' }), null);
  assert.equal(scanOptionsShapeError('asset', { scanType: 'ping', targets: ['10.0.0.0/24'] }), null);
  assert.match(scanOptionsShapeError('asset', { targets: '10.0.0.1' })!, /targets must be an array/);
  assert.match(scanOptionsShapeError('asset', { scanType: 'stealth' })!, /scanType must be one of/);
  assert.match(scanOptionsShapeError('asset', { assignedShipperId: -1 })!, /positive integer/);
  assert.match(scanOptionsShapeError('container', { all_images: 'yes' })!, /all_images must be a boolean/);
  assert.equal(scanOptionsShapeError('container', {}), null);
  assert.equal(scanOptionsShapeError('vulnerability', { templateSelection: { cves: true }, rateLimit: 50, timeout: 600000 }), null);
  assert.match(scanOptionsShapeError('vulnerability', { rateLimit: 0 })!, /rateLimit/);
  assert.match(scanOptionsShapeError('vulnerability', { timeout: 5 })!, /timeout/);
  assert.match(scanOptionsShapeError('log_discovery', { mode: 'loud' })!, /mode must be one of/);
  assert.match(scanOptionsShapeError('log_discovery', { manual_cidrs: '10.0.0.0/24' })!, /manual_cidrs must be an array/);
  assert.match(scanOptionsShapeError('asset', [])!, /must be an object/);
});

test('template selections: the shapes the form and scanner use', () => {
  assert.equal(templateSelectionError({ all: true }), null);
  assert.equal(templateSelectionError({ templates: ['http/', 'ssl/'], severities: ['high'], excludeTags: ['dos'] }), null);
  assert.equal(templateSelectionError({ templates: ['http/cves/2024/CVE-2024-0001.yaml'] }), null);
  assert.match(templateSelectionError({ templates: ['../etc/passwd'] })!, /not a valid template/);
  assert.match(templateSelectionError({ tags: ['a b'] })!, /not a valid tag/);
  assert.match(templateSelectionError({ severities: ['urgent'], cves: true })!, /severities/);
  assert.match(templateSelectionError({ wat: 1 })!, /unknown key/);
  assert.match(templateSelectionError({ templates: [] })!, /selects no templates/);
});

test('missing inputs, and the targets each type names', () => {
  assert.deepEqual(missingScanInputs('asset', { scanType: 'ping' }), ['targets']);
  assert.deepEqual(missingScanInputs('asset', { targets: ['  '] }), ['targets']);
  assert.deepEqual(missingScanInputs('asset', { targets: ['10.0.0.0/24'] }), []);
  assert.deepEqual(missingScanInputs('vulnerability', { templateSelection: { cves: true } }), ['target']);
  assert.deepEqual(missingScanInputs('container', {}), ['image_ref']);
  assert.deepEqual(missingScanInputs('container', { all_images: true }), []);
  assert.deepEqual(missingScanInputs('log_discovery', { mode: 'passive' }), []);
  assert.deepEqual(scheduleTargets('log_discovery', { manual_cidrs: ['10.1.0.0/16'] }), ['10.1.0.0/16']);
  assert.deepEqual(scheduleTargets('vulnerability', { target: 'nas.lan' }), ['nas.lan']);
  assert.deepEqual(scheduleTargets('container', { image_ref: 'x' }), []);
});

test('a log discovery run that would sweep unconfirmed public CIDRs is refused', async () => {
  const schedule = {
    id: 1,
    name: 'disc',
    scan_type: 'log_discovery',
    scan_options: { mode: 'active', manual_cidrs: ['8.8.8.0/24'] },
    created_by: null,
  } as unknown as ScheduledScan;
  await assert.rejects(triggerScheduledScan(schedule), /public address space not confirmed/);
});
