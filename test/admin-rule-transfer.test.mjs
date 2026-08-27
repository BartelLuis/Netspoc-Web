import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(repositoryRoot, 'admin.html'), 'utf8');
const script = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match => match[1]).filter(source => source.trim()).at(-1);

function functionSource(name) {
  const start = script.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} is missing`);
  const next = script.indexOf('\nfunction ', start + 1);
  return script.slice(start, next < 0 ? script.length : next);
}

test('rule editor exposes copy and move controls with a target service', () => {
  assert.match(html, /class="rule-target-service"/);
  assert.doesNotMatch(html, /class="rule-target-service"[^>]*data-field/);
  assert.match(html, /class="copy-rule">Kopieren/);
  assert.match(html, /class="move-rule">Verschieben/);
});

function transferContext() {
  const current = { dataset: { serviceEditorId: '1' } };
  const targetList = { appended: null, appendChild(node) { this.appended = node; } };
  const targetDetails = { open: false };
  const target = { dataset: { serviceEditorId: '2' }, nameField: { value: '120-OK-Verkehr' }, targetList, targetDetails };
  const select = { value: '2' };
  const rule = { select };
  const calls = { adds: [], messages: [] };
  const context = {
    derivedRuleFields: ['stable_rule_id', 'short_id', 'policy_name', 'policy_comment', 'naming_version'],
    $: (selector, root) => {
      if (selector === '.rule-target-service' && root === rule) return select;
      if (selector === '[data-field=name]' && root === target) return target.nameField;
      if (selector === '.rule-list' && root === target) return targetList;
      if (selector === '.rules-details' && root === target) return targetDetails;
      throw new Error(`Unexpected selector ${selector}`);
    },
    $$: selector => selector === '.service' ? [current, target] : [],
    values: () => ({ action: 'permit', sources: ['network:a'], stable_rule_id: 'old', short_id: 'ABCDE', policy_name: 'old-name' }),
    add: (type, data) => calls.adds.push({ type, data }),
    message: (text, error = false) => calls.messages.push({ text, error }),
    refreshRuleServiceTargets: () => {},
    updateRuleCounts: () => {},
    schedulePolicyNamePreview: () => {},
  };
  vm.createContext(context);
  vm.runInContext(functionSource('transferRule'), context);
  context.refreshRuleServiceTargets = () => {};
  context.updateRuleCounts = () => {};
  return { context, current, target, rule, calls };
}

test('copying creates an independent rule in the selected service', () => {
  const { context, target, rule, calls } = transferContext();
  context.transferRule(rule, 'copy');
  assert.equal(calls.adds.length, 1);
  assert.equal(calls.adds[0].type, 'rule');
  assert.equal(calls.adds[0].data.parent, target);
  assert.equal(calls.adds[0].data.open, true);
  assert.equal(calls.adds[0].data.stable_rule_id, undefined);
  assert.equal(calls.adds[0].data.short_id, undefined);
  assert.equal(calls.adds[0].data.policy_name, undefined);
});

test('moving reuses the rule row and opens the selected service', () => {
  const { context, target, rule, calls } = transferContext();
  context.transferRule(rule, 'move');
  assert.equal(target.targetList.appended, rule);
  assert.equal(target.targetDetails.open, true);
  assert.equal(calls.adds.length, 0);
});
