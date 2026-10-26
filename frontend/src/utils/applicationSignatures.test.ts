import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  docToForm,
  docToYaml,
  emptyForm,
  formToDoc,
  idFromName,
  kindsWithoutTests,
  linesToList,
  mergeDrafts,
  listToLines,
  testInputLabel,
  usedKinds,
  yamlToDoc,
  unmatchedKindLabel,
} from './applicationSignatures.ts';

const PLEX = `schema: siembox.app/v1
id: plex
name: Plex Media Server
vendor: Plex
category: media-server
description: Media server.
website: https://www.plex.tv
cpe: { vendor: plex, product: media_server }
match:
  syslog_program: [plex]
  service:
    names: [plexmediaserver]
    banner: ['^Plex Media Server (\\d[\\w.-]*)']
  container_image: [plexinc/pms-docker]
  package: [plexmediaserver]
  user_agent: ['^PlexMediaServer/(\\d+(?:\\.\\d+)+)']
  dns: [plex.tv]
  os: { family: linux, pretty_name: '^Ubuntu (\\d+)' }
tests:
  - source: syslog_program
    input: plex
  - source: container_image
    input: 'plexinc/pms-docker:latest'
    version: null
  - source: service
    input: { name: http, version: 'Plex Media Server 1.40' }
    version: '1.40'
  - source: user_agent
    input: curl/8.0
    match: false
`;

describe('signature form', () => {
  it('a catalog document survives form -> document -> YAML -> document', () => {
    const doc = yamlToDoc(PLEX).doc;
    const form = docToForm(doc);
    assert.equal(form.cpeProduct, 'media_server');
    assert.deepEqual(form.serviceBanner, ['^Plex Media Server (\\d[\\w.-]*)']);
    assert.equal(form.tests[1].version, 'none');
    assert.equal(form.tests[2].serviceVersion, 'Plex Media Server 1.40');
    assert.equal(form.tests[3].shouldMatch, false);
    const back = formToDoc(form);
    assert.deepEqual(back, doc);
    assert.deepEqual(yamlToDoc(docToYaml(back)).doc, doc);
  });

  it('empty fields and matchers are left out; blank list lines dropped', () => {
    const f = emptyForm();
    f.id = 'acme';
    f.name = ' Acme ';
    f.vendor = 'Acme';
    f.category = 'web-server';
    f.syslog_program = linesToList('acmed\n\n  acme-worker \n');
    const doc = formToDoc(f);
    assert.deepEqual(doc, { schema: 'siembox.app/v1', id: 'acme', name: 'Acme', vendor: 'Acme', category: 'web-server', match: { syslog_program: ['acmed', 'acme-worker'] }, tests: [] });
    assert.equal(listToLines(['a', 'b']), 'a\nb');
  });

  it('which matcher kinds still need a test', () => {
    const f = docToForm(yamlToDoc(PLEX).doc);
    assert.deepEqual(usedKinds(f), ['syslog_program', 'service', 'container_image', 'package', 'user_agent', 'dns', 'os']);
    assert.deepEqual(kindsWithoutTests(f), ['package', 'user_agent', 'dns', 'os'], 'a must-not-match test does not count');
  });

  it('helpers: ids, test labels, bad YAML, kind labels', () => {
    assert.equal(idFromName('Acme Server 2!'), 'acme-server-2');
    assert.equal(testInputLabel(docToForm(yamlToDoc(PLEX).doc).tests[2]), 'http · Plex Media Server 1.40');
    assert.match(yamlToDoc('a: [').error ?? '', /unexpected end|flow collection|end of the stream/i);
    assert.equal(unmatchedKindLabel('package'), 'Installed package');
    assert.equal(unmatchedKindLabel('other'), 'other');
  });
});

describe('drafts', () => {
  it('several values become one draft: matchers merged, tests appended, no duplicates', () => {
    const merged = mergeDrafts([
      { id: 'acme', name: 'Acme', match: { package: ['acme-agent'] }, tests: [{ source: 'package', input: 'acme-agent' }] },
      { id: 'acmed', name: 'Acmed', match: { syslog_program: ['acmed'], package: ['acme-agent'] }, tests: [{ source: 'syslog_program', input: 'acmed' }] },
      { id: 'x', match: { service: { names: ['acme-rpc'] } }, tests: [] },
    ]);
    assert.equal(merged.id, 'acme');
    assert.deepEqual(merged.match, { package: ['acme-agent'], syslog_program: ['acmed'], service: { names: ['acme-rpc'] } });
    assert.equal(merged.tests.length, 2);
  });
});
