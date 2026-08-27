import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = await readFile(join(repositoryRoot, 'app/model/Rule.js'), 'utf8');

test('rule model reads the backend has_user field', () => {
  assert.match(source, /name:\s*['"]has_user['"],\s*mapping:\s*['"]has_user['"]/);
  assert.doesNotMatch(source, /mapping:\s*['"]hasuser['"]/);
});
