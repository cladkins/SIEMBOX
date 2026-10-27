import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canCancelJob,
  formatAge,
  isActiveJob,
  jobBadgeText,
  jobKindLabel,
  jobOriginLabel,
  publicTargetGate,
  replaceTargetToken,
  scanStatusLabel,
  scanStatusTagType,
} from './shipperJobs.ts';

describe('shipper jobs', () => {
  it('labels kinds and origins', () => {
    assert.equal(jobKindLabel('nmap'), 'Asset scan (nmap)');
    assert.equal(jobKindLabel('nuclei'), 'Vulnerability scan (nuclei)');
    assert.equal(jobKindLabel('discovery'), 'Log discovery sweep');
    assert.equal(jobOriginLabel({ page: 'assets' }), 'Assets page');
    assert.equal(jobOriginLabel({ page: 'log_discovery' }), 'Log Discovery page');
    assert.equal(jobOriginLabel({ page: 'scheduled_scans', scheduledScanName: 'Nightly LAN' }), 'Scheduled scan "Nightly LAN"');
    assert.equal(jobOriginLabel({ page: 'scheduled_scans' }), 'Scheduled scan');
    assert.equal(jobOriginLabel(null), 'Unknown');
  });

  it('formats ages', () => {
    assert.equal(formatAge(-3), '0s');
    assert.equal(formatAge(45), '45s');
    assert.equal(formatAge(12 * 60 + 5), '12m');
    assert.equal(formatAge(3 * 3600), '3h');
    assert.equal(formatAge(3 * 3600 + 5 * 60), '3h 5m');
    assert.equal(formatAge(2 * 86400 + 4 * 3600 + 59), '2d 4h');
    assert.equal(formatAge(7 * 86400), '7d');
  });

  it('gates cancel the way the API does: analyst for an asset scan, operator for the rest', () => {
    assert.equal(canCancelJob('viewer', 'nmap'), false);
    assert.equal(canCancelJob('analyst', 'nmap'), true);
    assert.equal(canCancelJob('analyst', 'nuclei'), false);
    assert.equal(canCancelJob('analyst', 'discovery'), false);
    assert.equal(canCancelJob('operator', 'nuclei'), true);
    assert.equal(canCancelJob('admin', 'discovery'), true);
    assert.equal(canCancelJob(undefined, 'nmap'), false);
    assert.equal(canCancelJob('root', 'nmap'), false);
  });

  it('badges and statuses', () => {
    assert.equal(jobBadgeText(2, 0), '2 queued');
    assert.equal(jobBadgeText(0, 1), '1 running');
    assert.equal(jobBadgeText(2, 1), '2 queued · 1 running');
    assert.equal(jobBadgeText(undefined, null), '');
    assert.equal(isActiveJob({ status: 'queued' }), true);
    assert.equal(isActiveJob({ status: 'running' }), true);
    assert.equal(isActiveJob({ status: 'expired' }), false);
    assert.equal(scanStatusTagType('expired'), 'danger');
    assert.equal(scanStatusTagType('queued'), 'info');
    assert.equal(scanStatusTagType('mystery'), '');
    assert.equal(scanStatusLabel('expired'), 'expired (never ran)');
    assert.equal(scanStatusLabel('completed'), 'completed');
  });

  it('blocks a form with unconfirmed public targets, and sends the flag only when needed', () => {
    assert.deepEqual(
      { blocked: publicTargetGate(['192.168.1.0/24'], false).blocked, allow: publicTargetGate(['192.168.1.0/24'], true).allowPublicTargets },
      { blocked: false, allow: false }
    );
    const typo = publicTargetGate(['192.169.1.0/24'], false);
    assert.equal(typo.blocked, true);
    assert.equal(typo.allowPublicTargets, false);
    assert.equal(typo.report.publicTargets[0].suggestion, '192.168.1.0/24');
    const confirmed = publicTargetGate(['192.169.1.0/24'], true);
    assert.equal(confirmed.blocked, false);
    assert.equal(confirmed.allowPublicTargets, true);
    assert.equal(publicTargetGate(['nas.lan'], false).blocked, false, 'a hostname only warns');
  });

  it('replaces one whole target in free text, keeping separators', () => {
    assert.equal(replaceTargetToken('10.0.0.1\n192.169.1.0/24\n', '192.169.1.0/24', '192.168.1.0/24'), '10.0.0.1\n192.168.1.0/24\n');
    assert.equal(replaceTargetToken('192.169.1.1, 192.169.1.10', '192.169.1.1', '192.168.1.1'), '192.168.1.1, 192.169.1.10');
  });
});
