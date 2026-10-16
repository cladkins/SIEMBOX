import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_REDIRECT_LENGTH, safeRedirect, type Resolve } from './safeRedirect.ts';

/** A stand-in for router.resolve over a few of the app's routes (no catch-all, like the real table). */
const ROUTES: Record<string, string> = {
  '/': 'Dashboard',
  '/graph': 'ContextGraph',
  '/alerts': 'Alerts',
  '/threat-intel': 'ThreatIntel',
  '/login': 'Login',
  '/change-password': 'ChangePassword',
};
const resolve: Resolve = (path) => {
  const pathname = new URL(path, 'http://x.invalid').pathname;
  const name = ROUTES[pathname];
  return name ? { name, matched: [{}], fullPath: path } : { name: undefined, matched: [], fullPath: path };
};

describe('safeRedirect', () => {
  it('keeps an in-app path with its query', () => {
    const target = '/graph?entity=ip%3A198.51.100.7&window=30d&x=user%3Aroot';
    assert.equal(safeRedirect(target, resolve), target);
    assert.equal(safeRedirect('/', resolve), '/');
    assert.equal(safeRedirect('/alerts?alert=812#details', resolve), '/alerts?alert=812#details');
  });

  it('refuses other hosts', () => {
    for (const value of ['//evil.example', '//evil.example/graph', '/\\evil.example', '/\\/evil.example', 'https://evil.example/graph', 'http:evil.example', 'evil.example/graph']) {
      assert.equal(safeRedirect(value, resolve), null, value);
    }
  });

  it('refuses script and data URLs', () => {
    for (const value of ['javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'data:text/html,hi', ' /graph', '\t/graph']) {
      assert.equal(safeRedirect(value, resolve), null, value);
    }
  });

  it('refuses a backslash that a browser would read as a slash to another host', () => {
    assert.equal(safeRedirect('/graph/..\\..\\\\evil.example', resolve), null);
  });

  it('refuses control characters', () => {
    for (const value of ['/graph\n', '/gr\u0000aph', '/graph\u007f', '/graph\u0085', '/\r\n//evil.example']) {
      assert.equal(safeRedirect(value, resolve), null, JSON.stringify(value));
    }
  });

  it('refuses the sign-in and password-change pages, and the wall display', () => {
    assert.equal(safeRedirect('/login', resolve), null);
    assert.equal(safeRedirect('/login?redirect=%2Fgraph', resolve), null);
    assert.equal(safeRedirect('/change-password', resolve), null);
    assert.equal(safeRedirect('/display', resolve), null);
    assert.equal(safeRedirect('/display#k=sbd1_abc', resolve), null);
    assert.equal(safeRedirect('/display/', resolve), null);
    assert.equal(safeRedirect('/display.html', resolve), null);
  });

  it('refuses a path no route matches', () => {
    assert.equal(safeRedirect('/nowhere', resolve), null);
  });

  it('refuses what is not a string, empty, or longer than 2,000 characters', () => {
    assert.equal(safeRedirect(undefined, resolve), null);
    assert.equal(safeRedirect(['/graph'], resolve), null);
    assert.equal(safeRedirect('', resolve), null);
    const long = `/graph?entity=user%3A${'a'.repeat(MAX_REDIRECT_LENGTH)}`;
    assert.equal(safeRedirect(long, resolve), null);
    const fits = `/graph?q=${'a'.repeat(MAX_REDIRECT_LENGTH - 9)}`;
    assert.equal(fits.length, MAX_REDIRECT_LENGTH);
    assert.equal(safeRedirect(fits, resolve), fits);
  });

  it('treats a resolver that throws as no target', () => {
    assert.equal(
      safeRedirect('/graph', () => {
        throw new Error('bad');
      }),
      null
    );
  });
});
