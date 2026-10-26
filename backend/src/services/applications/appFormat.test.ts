/**
 * The application signature format and its validator (validate-applications),
 * including the ReDoS gate the CLI runs on every signature regex.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  crossCheckApplications,
  domainMatcherProblem,
  imageGlobProblem,
  signatureRegexProblem,
  validateApplication,
  type AppSignature,
} from './appFormat';
import { redosProblems } from '../../scripts/validate-applications';

const base = (over: Record<string, unknown> = {}) => ({
  schema: 'siembox.app/v1',
  id: 'acme',
  name: 'Acme Server',
  vendor: 'Acme',
  category: 'web-server',
  match: { syslog_program: ['acmed'] },
  tests: [{ source: 'syslog_program', input: 'acmed' }],
  ...over,
});

test('a minimal signature validates and normalizes', () => {
  const v = validateApplication(base(), { strict: true, expectId: 'acme' });
  assert.deepEqual(v.errors, []);
  assert.equal(v.app!.match.syslog_program[0], 'acmed');
  assert.deepEqual(v.app!.match.service, { names: [], banner: [] });
  assert.equal(v.app!.tests[0].match, true);
});

test('structure: schema, id, file name, category, matchers, unknown keys', () => {
  const errs = (doc: unknown, opts = {}) => validateApplication(doc, { strict: true, ...opts }).errors.join(' | ');
  assert.match(errs(base({ schema: 'siembox.app/v2' })), /schema must be/);
  assert.match(errs(base({ id: 'Acme_Server' })), /kebab-case/);
  assert.match(errs(base(), { expectId: 'other' }), /must match the file name/);
  assert.match(errs(base({ category: 'toaster' })), /category must be one of/);
  assert.match(errs(base({ match: {} })), /no matchers/);
  assert.match(errs(base({ colour: 'red' })), /unknown key "colour"/);
  assert.match(errs(base({ match: { syslog_program: ['acmed'], magic: [] } })), /match: unknown key "magic"/);
  // Non-strict (the app reading a newer catalog): unknown keys are warnings.
  const lax = validateApplication(base({ colour: 'red' }), { strict: false });
  assert.equal(lax.ok, true);
  assert.match(lax.warnings.join(), /colour/);
  assert.match(errs(base({ website: 'javascript:alert(1)' })), /website must be an http\(s\) URL/);
  assert.match(errs(base({ cpe: { vendor: 'Acme Corp', product: 'x' } })), /cpe.vendor/);
  assert.match(errs(base({ supersedes: ['acme'] })), /supersedes lists the application itself/);
});

test('strict mode needs a matching test per matcher kind, and no test for a kind it lacks', () => {
  const doc = base({ match: { syslog_program: ['acmed'], dns: ['acme.example'] } });
  assert.match(validateApplication(doc, { strict: true }).errors.join(), /add at least one matching test for match.dns/);
  const extra = base({ tests: [{ source: 'syslog_program', input: 'acmed' }, { source: 'dns', input: 'x.acme.example' }] });
  assert.match(validateApplication(extra, { strict: true }).errors.join(), /a dns test, but the signature has no match.dns/);
  const neg = base({ tests: [{ source: 'syslog_program', input: 'other', match: false }] });
  assert.match(validateApplication(neg, { strict: true }).errors.join(), /matching test for match.syslog_program/, 'a negative test does not count');
});

test('matcher values: programs, images, domains, packages', () => {
  assert.equal(validateApplication(base({ match: { syslog_program: ['postfix/*'] }, tests: [{ source: 'syslog_program', input: 'postfix/smtpd' }] })).ok, true);
  assert.match(validateApplication(base({ match: { syslog_program: ['acme:d'] } })).errors.join(), /not a valid program name/);
  assert.equal(imageGlobProblem('*/linuxserver/plex'), null);
  assert.match(imageGlobProblem('nginx:latest') ?? '', /no tag/);
  assert.match(imageGlobProblem('*') ?? '', /three literal/);
  assert.match(imageGlobProblem('a/**') ?? '', /\*\*/);
  assert.equal(domainMatcherProblem('zoom.us'), null);
  assert.equal(domainMatcherProblem('*.plex.direct'), null);
  assert.match(domainMatcherProblem('com') ?? '', /two labels/);
  assert.match(domainMatcherProblem('Zoom.US') ?? '', /lower case/);
  assert.match(domainMatcherProblem('bad..example') ?? '', /invalid label/);
  // Docker Hub forms fold: docker.io/library/nginx is nginx.
  const v = validateApplication(base({ match: { container_image: ['docker.io/library/nginx'] }, tests: [{ source: 'container_image', input: 'nginx:1' }] }));
  assert.deepEqual(v.app!.match.container_image, ['nginx']);
  assert.match(validateApplication(base({ match: { syslog_program: ['acmed', 'ACMED'] } })).errors.join(), /listed twice/);
});

test('signature regexes: compile, one capture group at most, no named groups or backreferences, not empty-matching', () => {
  assert.equal(signatureRegexProblem('^Acme/(\\d+(?:\\.\\d+)*)'), null);
  assert.match(signatureRegexProblem('^Acme/(') ?? '', /does not compile/);
  assert.match(signatureRegexProblem('^(Acme)/(\\d+)') ?? '', /2 capture groups/);
  assert.match(signatureRegexProblem('^Acme/(?<v>\\d+)') ?? '', /named group/);
  assert.match(signatureRegexProblem('(a)\\1') ?? '', /backreference/);
  assert.match(signatureRegexProblem('.*') ?? '', /empty string/);
  assert.match(signatureRegexProblem('x'.repeat(201)) ?? '', /1 to 200/);
  assert.equal(signatureRegexProblem('(?=a)a'), null, 'a lookahead is not a group');
});

test('the ReDoS gate refuses a vulnerable user_agent regex and passes a linear one', () => {
  const unsafe = validateApplication(base({ match: { user_agent: ['^Acme/(\\d+(?:\\.\\d+)*)(?:\\s|\\S)*\\s*x$'] }, tests: [{ source: 'user_agent', input: 'Acme/1 x' }] }));
  assert.ok(unsafe.app);
  const bad = redosProblems(unsafe.app!);
  assert.equal(bad.errors.length, 1);
  assert.match(bad.errors[0], /ReDoS: regex at match.user_agent\[0\] is vulnerable/);

  const exp = validateApplication(base({ match: { user_agent: ['^(a+)+$'] }, tests: [{ source: 'user_agent', input: 'aaa' }] }));
  assert.match(redosProblems(exp.app!).errors.join(), /vulnerable \(exponential\)/);

  const safe = validateApplication(base({ match: { user_agent: ['^Acme/(\\d+(?:\\.\\d+)*)'] }, tests: [{ source: 'user_agent', input: 'Acme/1.2' }] }));
  assert.deepEqual(redosProblems(safe.app!).errors, []);
});

test('the set: duplicate ids, unknown supersedes, a value claimed twice', () => {
  const a = validateApplication(base()).app!;
  const b: AppSignature = { ...validateApplication(base({ id: 'beta', name: 'Beta' })).app!, supersedes: ['gamma'] };
  const problems = crossCheckApplications([a, b, a]).map((p) => `${p.id}: ${p.error}`);
  assert.ok(problems.some((p) => /acme: application id "acme" is used twice/.test(p)));
  assert.ok(problems.some((p) => /beta: supersedes "gamma"/.test(p)));
  assert.ok(problems.some((p) => /beta: match.syslog_program "acmed" is also claimed by acme/.test(p)));
  assert.equal(crossCheckApplications([b], { checkSupersedes: false }).length, 0);
});
