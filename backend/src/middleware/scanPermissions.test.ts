/**
 * requireScanPermission writes every denial to audit_logs. The client address
 * comes from req.ip, which follows one X-Forwarded-For hop (app.ts trusts one
 * proxy), so on a direct call to the API port it is whatever the caller sent.
 * A value that is not an address falls back to the TCP peer, so the row can
 * still be written, and a forged one keeps the peer in details.peerAddress.
 * Hermetic: AuditService.log is mocked. Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import type { Request, Response } from 'express';
import { AuditService } from '../services/audit/auditService';
import { ApiError } from './errorHandler';
import { auditSource, requireScanPermission, UserRole } from './scanPermissions';

const auditLog = mock.method(AuditService, 'log', async () => undefined);

function viewerRequest(ip: string | undefined, peer: string | undefined): Request {
  return {
    user: { id: 7, username: 'gate-viewer', email: 'gate-viewer@siembox.invalid', role: 'viewer' },
    ip,
    socket: { remoteAddress: peer },
    headers: { 'user-agent': 'scanPermissions.test' },
    path: '/scan',
    method: 'POST',
  } as unknown as Request;
}

test('auditSource: the client address, plus the TCP peer when the two differ', () => {
  assert.deepEqual(auditSource(viewerRequest('127.0.0.1', '127.0.0.1')), { ipAddress: '127.0.0.1' });
  // Behind the nginx frontend, or a direct call with a forged X-Forwarded-For.
  assert.deepEqual(auditSource(viewerRequest('10.9.9.9', '172.18.0.5')), { ipAddress: '10.9.9.9', peerAddress: '172.18.0.5' });
  // Not an address: the peer stands in.
  assert.deepEqual(auditSource(viewerRequest('not-an-ip', '127.0.0.1')), { ipAddress: '127.0.0.1' });
  assert.deepEqual(auditSource(viewerRequest(undefined, 'fe80::1%eth0')), { ipAddress: 'fe80::1' });
  // Nothing usable: NULL, which INET accepts.
  assert.deepEqual(auditSource(viewerRequest('not-an-ip', undefined)), { ipAddress: null });
});

test('a denial behind a bogus or forged X-Forwarded-For is audited with a valid address and the real peer', async () => {
  const gate = requireScanPermission(UserRole.Operator, 'container_scan');
  const cases: Array<[forwarded: string, ipAddress: string, peerAddress: string | undefined]> = [
    ['not-an-ip', '127.0.0.1', undefined],
    ['10.9.9.9', '10.9.9.9', '127.0.0.1'],
  ];
  for (const [forwarded, ipAddress, peerAddress] of cases) {
    auditLog.mock.resetCalls();
    const err = await new Promise((resolve) => gate(viewerRequest(forwarded, '127.0.0.1'), {} as Response, resolve));
    assert.ok(err instanceof ApiError && err.statusCode === 403, `${forwarded}: refused with 403`);
    assert.equal(auditLog.mock.callCount(), 1, `${forwarded}: the denial is audited`);
    const [entry] = auditLog.mock.calls[0].arguments as unknown as [
      { action: string; ipAddress: string | null; details: { peerAddress?: string } },
    ];
    assert.equal(entry.action, 'access.denied');
    assert.equal(entry.ipAddress, ipAddress, `${forwarded}: ip_address`);
    assert.equal(entry.details.peerAddress, peerAddress, `${forwarded}: details.peerAddress`);
  }
});
