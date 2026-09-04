import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(repositoryRoot, 'admin.html'), 'utf8');
const adminScript = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1])
  .filter((source) => source.trim())
  .at(-1);
const scriptLines = adminScript.split('\n');

function functionLine(name) {
  const source = scriptLines.find((line) => line.startsWith(`function ${name}(`) || line.startsWith(`async function ${name}(`));
  assert.ok(source, `${name} is missing`);
  return source;
}

test('user administration clearly saves accounts immediately outside policy workflow', () => {
  assert.match(html, /Benutzerkonten und Rollen werden separat und sofort gespeichert/);
  assert.match(html, /kein Bestandteil des Policy-Entwurfs und benötigen keine Freigabe/);
  assert.match(html, /id="add-user"/);
  assert.match(html, /class="primary save-user">Änderung speichern/);
  assert.match(html, /class="danger remove-user">Entfernen/);
  assert.match(html, /aria-label="Rolle" data-field="role"/);
  assert.doesNotMatch(html, /<th>Policy-Rolle<\/th>/);
});

test('policy serialization and rendering never contain or touch accounts', () => {
  const policySource = functionLine('policy');
  const renderPolicySource = functionLine('renderPolicy');

  assert.doesNotMatch(policySource, /\busers\b|\.user|user-list/);
  assert.doesNotMatch(renderPolicySource, /\busers\b|\.user|user-list/);
  assert.doesNotMatch(adminScript, /\brender\(result\.policy\)/);
  assert.match(adminScript, /renderPolicy\(result\.policy\)/);
});

test('account payload sends only the editable email and role fields', () => {
  const source = functionLine('userPayload');
  const node = {
    email: { value: '  New.User@example.net  ' },
    role: { value: 'reviewer' },
    source: { value: 'ldap' },
    active: { checked: false },
    directoryID: { value: 'forged-id' },
  };
  const context = {
    $: (selector, root) => {
      assert.equal(root, node);
      if (selector === '[data-field=email]') return root.email;
      if (selector === '[data-field=role]') return root.role;
      throw new Error(`Unexpected selector ${selector}`);
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context);

  assert.deepEqual(JSON.parse(JSON.stringify(context.userPayload(node))), {
    email: 'New.User@example.net',
    role: 'reviewer',
  });
  assert.doesNotMatch(source, /source|active|directory_id|username/);
});

test('dedicated user API implements versioned GET POST PUT and DELETE without policy workflow', () => {
  const loadSource = functionLine('loadUsers');
  const saveSource = functionLine('saveUser');
  const deleteSource = functionLine('deleteUser');
  const mutationSource = `${saveSource}\n${deleteSource}`;

  assert.match(loadSource, /request\('backend6\/admin\/users'\)/);
  assert.match(saveSource, /request\('backend6\/admin\/users'/);
  assert.match(saveSource, /method:persisted\?'PUT':'POST'/);
  assert.match(saveSource, /users_version:usersVersion/);
  assert.match(saveSource, /body\.revision=node\.userRevision/);
  assert.match(deleteSource, /request\('backend6\/admin\/users'/);
  assert.match(deleteSource, /method:'DELETE'/);
  assert.match(deleteSource, /email,revision:node\.userRevision,users_version:usersVersion/);
  assert.doesNotMatch(adminScript, /backend6\/admin\/users\//);
  assert.doesNotMatch(mutationSource, /admin\/(?:policy|stage|publish|reject|deploy)|draftVersion|canReview|Vier-Augen/);
});

test('existing account identity is immutable and every mutation refreshes the authoritative list', () => {
  const applySource = functionLine('applyUsersResult');
  const addSourceStart = adminScript.indexOf('function add(type,data={})');
  const addSourceEnd = adminScript.indexOf('\nfunction refreshOwners(', addSourceStart);
  const addSource = adminScript.slice(addSourceStart, addSourceEnd);

  assert.match(addSource, /node\.userRevision=data\.revision/);
  assert.match(addSource, /\[data-field=email\].*readOnly=persisted/);
  assert.match(addSource, /saveUser\(node\)/);
  assert.match(addSource, /deleteUser\(node\)/);
  assert.match(applySource, /usersVersion=result\.users_version/);
  assert.match(applySource, /renderUsers\(result\.users\)/);
  assert.match(functionLine('saveUser'), /applyUsersResult\(result\)/);
  assert.match(functionLine('deleteUser'), /applyUsersResult\(result\)/);
});

test('an LDAP-disabled current account loses its UI role immediately', () => {
  const applySource = functionLine('applyUsersResult');

  assert.match(applySource, /own&&own\.active!==false&&own\.role\?own\.role:''/);
});

test('LDAP preview and confirmation use only the account catalog version', () => {
  const previewSource = functionLine('syncLDAP');
  const confirmSource = functionLine('confirmLDAPSync');

  assert.match(previewSource, /users_version:usersVersion/);
  assert.match(confirmSource, /preview_token:/);
  assert.match(confirmSource, /users_version:usersVersion/);
  assert.match(confirmSource, /applyUsersResult\(result\)/);
  assert.doesNotMatch(`${previewSource}\n${confirmSource}`, /draftVersion|updateDraftMeta|X-Policy-Draft-Version/);
});

test('only administrators and developers receive immediate account controls', () => {
  const saveSource = functionLine('saveUser');
  const deleteSource = functionLine('deleteUser');
  const permissionSource = functionLine('applyRolePermissions');

  assert.match(adminScript, /canAdmin=\(\)=>currentRole==='admin'\|\|isDeveloper\(\)/);
  assert.match(saveSource, /!canAdmin\(\)/);
  assert.match(deleteSource, /!canAdmin\(\)/);
  assert.match(permissionSource, /#add-user/);
  assert.match(permissionSource, /!canAdmin\(\)\|\|usersMutationPending/);
  assert.match(functionLine('activateTab'), /\['users','requests'\]/);
});
