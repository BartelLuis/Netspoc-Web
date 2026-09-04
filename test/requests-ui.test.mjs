import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

async function source(...parts) {
  return readFile(join(root, ...parts), 'utf8');
}

test('Antragswesen is a lazy top-level card after Berechtigungen', async () => {
  const viewport = await source('app', 'view', 'Viewport.js');
  const accountCard = viewport.indexOf("{ xtype : 'accountview' }");
  const requestsCard = viewport.indexOf("{ xtype : 'requestsview' }");
  const devicesCard = viewport.indexOf("{ xtype : 'devicesview' }");
  const accountButton = viewport.indexOf("id           : 'btn_entitlement_tab'");
  const requestsButton = viewport.indexOf("id           : 'btn_requests_tab'");
  const devicesButton = viewport.indexOf("id           : 'btn_devices_tab'");
  assert.ok(accountCard >= 0 && accountCard < requestsCard && requestsCard < devicesCard);
  assert.ok(accountButton >= 0 && accountButton < requestsButton && requestsButton < devicesButton);
  assert.match(viewport, /text\s*:\s*'Antragswesen'/);

  const view = await source('app', 'view', 'Requests.js');
  assert.match(view, /alias:\s*'widget\.requestsview'/);
  assert.match(view, /src:\s*'about:blank'/);
  assert.match(view, /requests\.html\?embedded=1&_=/);

  const main = await source('app', 'controller', 'Main.js');
  assert.match(main, /btn_requests_tab/);
  assert.match(main, /item\.loadRequests\(\)/);

  const application = await source('app', 'Application.js');
  assert.match(application, /PolicyWeb\.view\.Requests/);
});

test('service request form uses structured existing-object selections', async () => {
  const html = await source('requests.html');
  for (const id of [
    'service-name', 'service-rule-name', 'service-description', 'service-owner',
    'service-sources', 'service-destinations', 'service-protocols',
    'request-reason', 'request-list',
  ]) {
    assert.match(html, new RegExp(`id="${id}"`), `${id} is missing`);
  }
  for (const id of [
    'service-rule-group', 'service-change-reference', 'service-purpose',
    'service-review-date', 'service-expires-at', 'service-rollback-owner',
    'service-tenant', 'service-target-context',
  ]) {
    assert.doesNotMatch(html, new RegExp(`id="${id}"`), `${id} must not be visible`);
  }
  assert.match(html, /id="service-rule-name"[^>]*required[^>]*maxlength="35"[^>]*pattern="\[A-Za-z0-9\]\[A-Za-z0-9_-\]\{0,34\}"/);
  assert.match(html, /id="service-sources"[^>]*multiple[^>]*required/);
  assert.match(html, /id="service-destinations"[^>]*multiple[^>]*required/);
  assert.match(html, /const rule=\{policy_name:[^}]*action:'permit',has_user:'none',sources,destinations,protocols,owner\}/);
  assert.match(html, /request_type:'new_service'/);
  assert.match(html, /base_version:baseVersion,reason,new_service:/);
  assert.match(html, /new_service:\{name:/);
  assert.match(html, /description:\$\('#service-description'\)\.value\.trim\(\)/);
  assert.match(html, /owners:\[owner\],rules:\[rule\]/);
  assert.doesNotMatch(html, /\b(?:rule_group|change_reference|review_date|expires_at|rollback_owner|tenant_mkz|target_context)\b/);
  assert.match(html, /requests\/context/);
  assert.match(html, /request\('requests'/);
  assert.match(html, /base_version:baseVersion/);
  assert.match(html, /data\.current!==true/);
  assert.match(html, /value\.startsWith\('fqdn:'\)/);
});

test('request list renders server data only through textContent and DOM nodes', async () => {
  const html = await source('requests.html');
  const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
    .map((match) => match[1])
    .filter((item) => item.trim());
  const script = inlineScripts.at(-1);
  assert.ok(script);
  assert.doesNotThrow(() => new Function(script));
  assert.doesNotMatch(script, /\.innerHTML\s*=/);
  assert.match(script, /\.textContent=/);
  assert.match(script, /\.replaceChildren\(/);
  assert.match(script, /pre\.textContent=requestDocument\(record\)/);
  assert.match(script, /credentials:'same-origin'/);
});

test('rules expose six explicit request actions bound to stable raw identity', async () => {
  const grid = await source('app', 'view', 'panel', 'grid', 'Rules.js');
  for (const label of ['+ Quelle', '\\u2212 Quelle', '+ Ziel', '\\u2212 Ziel', '+ Port', '\\u2212 Port']) {
    assert.ok(grid.includes(`text: '${label}'`), `${label} button is missing`);
  }
  assert.equal((grid.match(/requestOperation:/g) || []).length, 6);
  assert.equal((grid.match(/requestField:/g) || []).length, 6);

  const model = await source('app', 'model', 'Rule.js');
  for (const field of ['policy_name', 'stable_rule_id', 'current', 'service_name', 'active_owner', 'base_version', 'source_refs', 'destination_refs', 'protocol_refs']) {
    assert.match(model, new RegExp(`name: '${field}'`), `${field} model field is missing`);
  }
  assert.match(model, /node\.raw_src/);
  assert.match(model, /node\.raw_dst/);
  assert.match(model, /node\.raw_prt/);
  assert.match(grid, /header:\s*'Regelname'[\s\S]*?dataIndex:\s*'policy_name'/);
  assert.match(grid, /Ext\.String\.htmlEncode\(String\(value \|\| ''\)\)/);

  const controller = await source('app', 'controller', 'Service.js');
  assert.match(controller, /appstate\.isCurrentPolicy\(\)/);
  assert.match(controller, /request_type:\s*'rule_change'/);
  assert.match(controller, /rule_change:\s*\{/);
  assert.match(controller, /stable_rule_id:/);
  assert.match(controller, /base_version:/);
  assert.match(controller, /active_owner:/);
  assert.match(controller, /reason:/);
  assert.match(controller, /url:\s*'backend6\/requests'/);
  assert.match(controller, /url:\s*'backend6\/requests\/context'/);
  assert.match(controller, /data\.current !== true/);
  assert.match(controller, /currentValues\.length < 2/);
  assert.match(controller, /rules_store\.removeAll\(\)/);
  assert.match(controller, /record\.get\('service_name'\) === selectedService/);
  assert.match(controller, /record\.get\('active_owner'\) === appstate\.getOwner\(\)/);
  assert.match(controller, /controller\.getSelectedServiceName\(\) !== request\.service/);
  assert.match(controller, /request\.record\.get\('service_name'\) !== request\.service/);
  assert.match(controller, /request\.record\.get\('active_owner'\) !== request\.activeOwner/);
  assert.match(controller, /if \(!value \|\| !reason\)/);
  assert.doesNotMatch(controller, /fields\[[34]\]\.sortType/);
  assert.match(controller, /Auswahl oder Policystand geändert/);
  assert.match(controller, /ungültige Auswahldaten geliefert/);
  assert.doesNotMatch(controller, /Kontext inzwischen geändert|ungültige Kontextdaten|Antragskontext konnte nicht geladen werden/);

  const backend = await source('go', 'pkg', 'backend', 'getrules.go');
  assert.match(backend, /"policy_name":\s+rule\.PolicyName/);
  assert.match(backend, /"service":\s+service/);
  assert.match(backend, /"active_owner":\s+owner/);
});

test('current-policy state is explicit and fail closed', async () => {
  const appstate = await source('app', 'Appstate.js');
  assert.match(appstate, /state\.isCurrentPolicy = function/);
  assert.match(appstate, /history\.current === true/);
  assert.doesNotMatch(appstate, /return Boolean\(history\.current\)/);
});
