import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(repositoryRoot, 'admin.html'), 'utf8');
const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1])
  .filter((source) => source.trim());
const adminScript = inlineScripts.at(-1);

test('admin inline JavaScript has valid syntax', () => {
  assert.ok(adminScript, 'admin inline script is missing');
  assert.doesNotThrow(() => new vm.Script(adminScript, { filename: 'admin.html' }));
});

test('FQDN editor exposes ownership, filtering and rule target suggestions', () => {
  assert.match(html, /data-tab="fqdns"/);
  assert.match(html, /data-filter="fqdn"/);
  assert.match(html, /id="fqdn-template"/);
  assert.match(html, /data-field="fqdn"/);
  assert.match(html, /data-field="owner" required/);
  assert.match(html, /data-field="destinations" list="rule-destination-options"/);
  assert.match(html, /fqdn:web-api/);
});

test('service rules expose every supported user side', () => {
  assert.match(html, /data-field="has_user"/);
  assert.match(html, /<option value="src">Quelle<\/option>/);
  assert.match(html, /<option value="dst">Ziel<\/option>/);
  assert.match(html, /<option value="both">Quelle und Ziel<\/option>/);
  assert.match(html, /<option value="none">Keine<\/option>/);
});

test('rule user side survives render and serialization, with legacy values defaulting to source', () => {
  const normalizerSource = adminScript.split('\n').find((line) => line.startsWith('const validUserSides='));
  const valuesSource = adminScript.split('\n').find((line) => line.startsWith('function values('));
  assert.ok(normalizerSource && valuesSource, 'rule user-side helpers are missing');

  const context = {
    split: (value) => value.split(',').map((part) => part.trim()).filter(Boolean),
    $$: (selector, root) => {
      if (selector === '[data-field]') return root.fields;
      throw new Error(`Unexpected selector: ${selector}`);
    },
  };
  vm.createContext(context);
  vm.runInContext(`${normalizerSource}\n${valuesSource}\nglobalThis.normalizeUserSideForTest=normalizeUserSide`, context);

  const cases = [
    [undefined, 'src'],
    ['', 'src'],
    ['src', 'src'],
    ['dst', 'dst'],
    ['both', 'both'],
    ['none', 'none'],
  ];
  for (const [stored, expected] of cases) {
    const rule = { fields: [] };
    rule.fields = [{
      dataset: { field: 'has_user' },
      type: 'select-one',
      value: context.normalizeUserSideForTest(stored),
      closest: () => rule,
    }];
    assert.equal(context.values(rule).has_user, expected);
  }
});

test('policy serialization emits FQDNs and preserves hidden legacy metadata opaquely', () => {
  const valuesSource = adminScript.split('\n').find((line) => line.startsWith('function values('));
  const preserveSource = adminScript.split('\n').find((line) => line.startsWith('function preserveLegacyPolicyMetadata('));
  const policySource = adminScript.split('\n').find((line) => line.startsWith('function policy('));
  assert.ok(valuesSource && preserveSource && policySource, 'serialization functions are missing');

  const fqdn = { fields: [] };
  fqdn.fields = [
    { dataset: { field: 'name' }, type: 'text', value: 'web-api', closest: () => fqdn },
    { dataset: { field: 'fqdn' }, type: 'text', value: 'api.example.org', closest: () => fqdn },
    { dataset: { field: 'owner' }, type: 'select-one', value: 'NOC', closest: () => fqdn },
  ];

  const context = {
    legacyPolicyMetadata: {},
    legacyPolicyFieldNames: ['tenants', 'target_contexts', 'naming_catalog'],
    split: (value) => value.split(',').map((part) => part.trim()).filter(Boolean),
    $: (selector) => {
      if (selector === '#policy-name') return { value: 'policy' };
      throw new Error(`Unexpected selector: ${selector}`);
    },
    $$: (selector, root) => {
      if (selector === '[data-field]' && root === fqdn) return fqdn.fields;
      if (selector === '.fqdn') return [fqdn];
      if (['.owner', '.network', '.service'].includes(selector)) return [];
      throw new Error(`Unexpected selector: ${selector}`);
    },
  };
  vm.createContext(context);
  vm.runInContext(`${valuesSource}\n${preserveSource}\n${policySource}`, context);
  context.preserveLegacyPolicyMetadata({
    tenants: [{ mkz: 'M120', untouched: { value: true } }],
    target_contexts: [{ name: 'legacy-context', context_type: 'dedicated' }],
    naming_catalog: { version: 'v1', future_field: ['opaque'] },
  });

  assert.deepEqual(JSON.parse(JSON.stringify(context.policy())), {
    name: 'policy',
    tenants: [{ mkz: 'M120', untouched: { value: true } }],
    target_contexts: [{ name: 'legacy-context', context_type: 'dedicated' }],
    naming_catalog: { version: 'v1', future_field: ['opaque'] },
    owners: [],
    networks: [],
    fqdns: [{ name: 'web-api', fqdn: 'api.example.org', owner: 'NOC' }],
    services: [],
  });
});
