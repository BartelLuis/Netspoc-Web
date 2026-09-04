import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const indexHTML = await readFile(join(repositoryRoot, 'index.html'), 'utf8');

test('first-run form collects a user-chosen administrator credential', () => {
  assert.match(indexHTML, /id="setup-form"[^>]*hidden/);
  assert.match(indexHTML, /id="setup-token"[^>]*type="password"/);
  assert.match(indexHTML, /id="setup-email"[^>]*type="email"/);
  assert.match(indexHTML, /id="setup-password"[^>]*type="password"[^>]*minlength="12"[^>]*maxlength="256"/);
  assert.match(indexHTML, /id="setup-password-confirmation"[^>]*type="password"/);
  assert.doesNotMatch(indexHTML, /value="(?:admin|password|changeme|default)"/i);
});

test('first-run UI is gated by server initialization and uses the protected setup endpoint', () => {
  assert.match(indexHTML, /fetch\('backend6\/admin\/status'/);
  assert.match(indexHTML, /if \(status\.initialized\)/);
  assert.match(indexHTML, /fetch\('backend6\/setup'/);
  assert.match(indexHTML, /method: 'POST'/);
  assert.match(indexHTML, /'X-PolicyWeb-Bootstrap-Token': token\.value/);
  assert.match(indexHTML, /password_confirmation: confirmation\.value/);
  assert.match(indexHTML, /credentials: 'same-origin'/);
});

test('bootstrap and password values are never persisted and are cleared after submission', () => {
  assert.doesNotMatch(indexHTML, /localStorage|sessionStorage/);
  assert.match(indexHTML, /token\.value = ''/);
  assert.match(indexHTML, /password\.value = ''/);
  assert.match(indexHTML, /confirmation\.value = ''/);
  assert.doesNotMatch(indexHTML, /innerHTML\s*=/);
});
