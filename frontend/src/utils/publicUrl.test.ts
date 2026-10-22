import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { browserPublicUrl, previewAlertLink, publicUrlSourceText, type PublicUrlConfig } from './publicUrl.ts';

describe('browserPublicUrl', () => {
  it('is the origin when the UI is served at the root', () => {
    assert.equal(browserPublicUrl('https://siem.example.com', '/'), 'https://siem.example.com');
    assert.equal(browserPublicUrl('http://192.168.1.10:8420', undefined), 'http://192.168.1.10:8420');
  });
  it('adds the base path, without its trailing slash', () => {
    assert.equal(browserPublicUrl('https://example.com', '/siembox/'), 'https://example.com/siembox');
  });
  it('ignores a relative base (./) rather than gluing it on', () => {
    assert.equal(browserPublicUrl('https://example.com', './'), 'https://example.com');
  });
});

describe('previewAlertLink', () => {
  it('is the alert deep link on the effective public URL', () => {
    assert.equal(previewAlertLink('https://example.com/siembox'), 'https://example.com/siembox/alerts?alert=ALR-1234');
  });
  it('is empty without a public URL', () => {
    assert.equal(previewAlertLink(''), '');
  });
});

describe('publicUrlSourceText', () => {
  const base: PublicUrlConfig = { public_url: '', env_public_url: '', effective_public_url: '', source: 'none' };
  it('says when there are no links', () => {
    assert.match(publicUrlSourceText(base), /no link/);
  });
  it('names the env var when it applies', () => {
    const env = { ...base, env_public_url: 'https://env.example.com', effective_public_url: 'https://env.example.com', source: 'env' as const };
    assert.match(publicUrlSourceText(env), /SIEMBOX_PUBLIC_URL \(https:\/\/env\.example\.com\)/);
  });
});
