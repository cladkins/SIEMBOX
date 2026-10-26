import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canRequestScans,
  formatDuration,
  hasActiveScans,
  scanStatusTag,
  scanStatusText,
  scanTypeLabel,
  summarizeScan,
  supportsAdhocScans,
  triggerLabel,
} from './endpointScans.ts';

describe('endpoint scans', () => {
  it('summarizes each scan type', () => {
    assert.equal(summarizeScan({ scan_type: 'vuln', summary: { findings: 12, new: 2, resolved: 1 } }), '12 findings · 2 new · 1 no longer reported');
    assert.equal(summarizeScan({ scan_type: 'packages', summary: { packages: 1500, added: 3, removed: 1, unchanged: 1497 } }), '1,500 packages · +3 · −1 · 1,497 unchanged');
    assert.equal(summarizeScan({ scan_type: 'yara', summary: { hits: 1, new_hits: 1, full: true } }), '1 hit · full scan');
    assert.equal(summarizeScan({ scan_type: 'yara', summary: { hits: 2, new_hits: 0, full: false } }), '2 hits · 0 new · changed files only');
    assert.equal(summarizeScan({ scan_type: 'inventory', summary: { changed: false, software: 1 } }), 'no change · 1 program');
    assert.equal(summarizeScan({ scan_type: 'vuln', summary: null }), '');
    assert.equal(summarizeScan({ scan_type: 'vuln', summary: { findings: 'x' } }), '');
  });

  it('labels statuses and triggers', () => {
    assert.equal(scanStatusTag('succeeded'), 'success');
    assert.equal(scanStatusTag('failed'), 'danger');
    assert.equal(scanStatusTag('expired'), 'warning');
    assert.equal(scanStatusTag('running'), 'primary');
    assert.equal(scanStatusTag('pending'), 'info');
    assert.equal(scanStatusText({ status: 'pending' }, false), 'queued — agent offline');
    assert.equal(scanStatusText({ status: 'pending' }, true), 'queued');
    assert.equal(scanStatusText({ status: 'running' }, false), 'running');
    assert.equal(triggerLabel('console'), 'on demand');
    assert.equal(triggerLabel('schedule'), 'scheduled');
    assert.equal(triggerLabel('startup'), 'startup');
    assert.equal(scanTypeLabel('packages'), 'Packages');
  });

  it('knows when to keep refreshing', () => {
    assert.equal(hasActiveScans([{ status: 'succeeded' }, { status: 'running' }]), true);
    assert.equal(hasActiveScans([{ status: 'pending' }]), true);
    assert.equal(hasActiveScans([{ status: 'failed' }, { status: 'expired' }, { status: 'cancelled' }]), false);
  });

  it('formats durations', () => {
    assert.equal(formatDuration(null), '—');
    assert.equal(formatDuration(4_400), '4s');
    assert.equal(formatDuration(125_000), '2m 5s');
    assert.equal(formatDuration(3_725_000), '1h 2m');
  });

  it('gates requests by role and agent capability', () => {
    assert.equal(canRequestScans('admin'), true);
    assert.equal(canRequestScans('operator'), true);
    assert.equal(canRequestScans('analyst'), true);
    assert.equal(canRequestScans('viewer'), false);
    assert.equal(canRequestScans(undefined), false);
    assert.equal(supportsAdhocScans({ capabilities: ['adhoc_scans'] }), true);
    assert.equal(supportsAdhocScans({ capabilities: null }), false);
    assert.equal(supportsAdhocScans(null), false);
  });
});
