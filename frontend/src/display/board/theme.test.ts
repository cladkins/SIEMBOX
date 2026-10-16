/**
 * Every text and fill pair the wall uses must reach WCAG 4.5 : 1
 * (BIG-DISPLAY.md §5.1). Reads the tokens from theme.css itself, so a colour
 * changed there is checked here.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SEV_COLOR } from './severity.ts';

const css = readFileSync(new URL('./theme.css', import.meta.url), 'utf8');
const tokens = Object.fromEntries([...css.matchAll(/(--bd-[\w-]+):\s*(#[0-9a-fA-F]{6})\b/g)].map((m) => [m[1], m[2]]));

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe('wall contrast', () => {
  it('reads every token from theme.css', () => {
    for (const t of ['--bd-bg', '--bd-panel', '--bd-text', '--bd-text-2', '--bd-critical', '--bd-warning', '--bd-on-fill']) {
      assert.ok(tokens[t], `${t} is defined as a hex colour`);
    }
  });

  const pairs: Array<[string, string]> = [
    ['--bd-text', '--bd-panel'],
    ['--bd-text', '--bd-bg'],
    ['--bd-text-2', '--bd-panel'],
    ['--bd-text-2', '--bd-bg'],
    ['--bd-critical', '--bd-panel'],
    ['--bd-warning', '--bd-panel'],
    ['--bd-on-fill', '--bd-critical'],
    ['--bd-on-fill', '--bd-warning'],
    ['--bd-text', '--bd-highlight'],
  ];
  for (const [fg, bg] of pairs) {
    it(`${fg} on ${bg} is at least 4.5 : 1`, () => {
      const ratio = contrast(tokens[fg], tokens[bg]);
      assert.ok(ratio >= 4.5, `${fg} on ${bg} is ${ratio.toFixed(2)} : 1`);
    });
  }

  it('the app severity colours read on a panel', () => {
    for (const [sev, colour] of Object.entries(SEV_COLOR)) {
      const ratio = contrast(colour, tokens['--bd-panel']);
      assert.ok(ratio >= 4.5, `${sev} ${colour} is ${ratio.toFixed(2)} : 1`);
    }
  });

  it('matches the spec figures for body text', () => {
    assert.ok(contrast('#E8EDF3', '#121A24') > 14.5);
  });
});
