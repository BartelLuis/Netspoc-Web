import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('Devices is a lazy top-level card immediately before Administration', async () => {
  const viewport = await readFile(join(root, 'app', 'view', 'Viewport.js'), 'utf8');
  const devicesCard = viewport.indexOf("{ xtype : 'devicesview' }");
  const adminCard = viewport.indexOf("{ xtype : 'adminview' }");
  const devicesButton = viewport.indexOf("id           : 'btn_devices_tab'");
  const adminButton = viewport.indexOf("id           : 'btn_admin_tab'");
  assert.ok(devicesCard >= 0 && devicesCard < adminCard);
  assert.ok(devicesButton >= 0 && devicesButton < adminButton);

  const view = await readFile(join(root, 'app', 'view', 'Devices.js'), 'utf8');
  assert.match(view, /alias:\s*'widget\.devicesview'/);
  assert.match(view, /src:\s*'about:blank'/);
  assert.match(view, /devices\.html\?embedded=1&_=/);

  const main = await readFile(join(root, 'app', 'controller', 'Main.js'), 'utf8');
  assert.match(main, /btn_devices_tab/);
  assert.match(main, /item\.loadDevices\(\)/);
  for (const role of ['admin', 'editor', 'reviewer', 'deployer', 'developer']) {
    assert.match(main, new RegExp(`data\\.role === '${role}'`));
  }
});

test('Devices page performs safe, cancellable same-origin routing requests', async () => {
  const html = await readFile(join(root, 'devices.html'), 'utf8');
  assert.match(html, /name="source"\s+required/);
  assert.match(html, /name="destination"\s+required/);
  assert.match(html, /name="vrf"[^>]+value="0"/);
  assert.match(html, /name="vrf"[^>]+min="0"[^>]+max="251"/);
  assert.match(html, /backend6\/['"]?\+path/);
  assert.match(html, /devices\/routes\?/);
  assert.match(html, /fortinet\/status/);
  assert.match(html, /new AbortController\(\)/);
  assert.match(html, /escapeHTML\(device\.error\)/);
  assert.match(html, /Rückroute zum Quellnetz/);
  assert.match(html, /Vorwärtsroute zum Zielnetz/);
  assert.match(html, /Transit-Kandidat/);
  assert.doesNotMatch(html, /access_token/i);
});

test('Routing UI discards stale updates and renders structured HTTP failures', async () => {
  const html = await readFile(join(root, 'devices.html'), 'utf8');
  assert.match(html, /catch\(error\)\{if\(error\.name===['"]AbortError['"]\)throw error;/);
  assert.match(html, /error\.data=data/);

  const submitStart = html.indexOf("$('#routing-form').addEventListener('submit'");
  const submitEnd = html.indexOf("$('#refresh-devices').addEventListener", submitStart);
  assert.ok(submitStart >= 0 && submitEnd > submitStart);
  const submit = html.slice(submitStart, submitEnd);
  const hideResults = submit.indexOf("$('#routing-results').hidden=true");
  const startRequest = submit.indexOf("await request('devices/routes?");
  assert.ok(hideResults >= 0 && hideResults < startRequest);
  assert.match(submit, /catch\(error\)\{if\(error\.name===['"]AbortError['"]\|\|requestID!==routeRequest\)return;/);
  assert.match(submit, /if\(error\.data&&Array\.isArray\(error\.data\.devices\)\)renderRouting\(error\.data\)/);
});

test('FortiGate management is admin/developer-gated, secret-safe and fully wired', async () => {
  const html = await readFile(join(root, 'devices.html'), 'utf8');
  assert.match(html, /id="fortigate-management"[^>]*hidden/);
  assert.match(html, /request\('admin\/status'\)/);
  assert.match(html, /const canManageFortiGates=\(\)=>currentRole==='admin'\|\|currentRole==='developer'/);
  assert.match(html, /\['admin','developer'\]\.includes\(status\.role\)/);
  assert.doesNotMatch(html, /currentRole!==['"]admin['"]|status\.role!==['"]admin['"]/);
  assert.match(html, /id="fortigate-token"[^>]*type="password"[^>]*autocomplete="new-password"/);
  assert.match(html, /request\('admin\/fortigates'/);
  assert.match(html, /method:wasEditing\?'PUT':'POST'/);
  assert.match(html, /method:'DELETE'/);
  assert.match(html, /admin\/fortigates\/test/);
  assert.match(html, /managed_by===['"]web['"]&&record\.editable===true/);
  assert.match(html, /fortigate-form['"]\)\.addEventListener\(['"]submit['"],saveFortiGate\)/);
  assert.match(html, /fortigate-management-list['"]\)\.addEventListener\(['"]click['"]/);
  assert.match(html, /loadFortiGateAdministration\(\)/);
  assert.match(html, /tokenInput\.value=['"]{2}/);
  assert.match(html, /CA-Zertifikat.*neuer API-Token/);
  assert.doesNotMatch(html, /localStorage|sessionStorage|token_env|access_token/i);

  const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1])
    .filter(source => source.trim());
  assert.doesNotThrow(() => new Function(inlineScripts.at(-1)));
});

test('Container image includes the Devices page and routing resources', async () => {
  const dockerfile = await readFile(join(root, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /COPY[^\n]*devices\.html/);
  assert.match(dockerfile, /-a -f \/srv\/policyweb\/devices\.html/);
  assert.match(dockerfile, /html\/ip_search_tooltip/);
});
