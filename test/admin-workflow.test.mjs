import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(repositoryRoot, 'admin.html'), 'utf8');

test('rule editor uses a manual name and hides naming and lifecycle configuration', () => {
  assert.match(html, /<th>Regelname<\/th>/);
  assert.match(html, /data-field="policy_name" required maxlength="35" pattern="\[A-Za-z0-9\]\[A-Za-z0-9_-\]\{0,34\}"/);
  for (const field of [
    'change_reference', 'purpose', 'owner', 'review_date', 'expires_at',
    'rollback_owner', 'tenant_mkz', 'target_context', 'rule_group',
  ]) {
    if (field === 'owner') {
      assert.match(html, /aria-label="Verantwortungsbereich" data-field="owner"/);
    } else {
      assert.doesNotMatch(html, new RegExp(`data-field="${field}"`), `${field} must not be visible`);
    }
  }
  assert.doesNotMatch(html, /rule-name-preview|policy-name-preview|updateRuleNamePreview|applyDerivedPolicy/);
  assert.doesNotMatch(html, /data-tab="catalogs"|id="catalogs"|id="tenant-options"|id="target-context-options"/);
  assert.doesNotMatch(html, /id="tenant-template"|id="target-context-template"|id="catalog-service-(?:code|short)-template"/);
  assert.match(html, /const serverRuleFields=\['stable_rule_id','short_id','policy_comment','naming_version'\]/);
  assert.match(html, /const legacyRuleFields=\['rule_group','change_reference','review_date','expires_at','rollback_owner','purpose','tenant_mkz','target_context'\]/);
  assert.match(html, /const opaqueRuleFields=\[\.\.\.serverRuleFields,\.\.\.legacyRuleFields\]/);
  assert.match(html, /const legacyPolicyFieldNames=\['tenants','target_contexts','naming_catalog'\]/);
  assert.match(html, /function preserveLegacyPolicyMetadata\(/);
  assert.match(html, /\.\.\.legacyPolicyMetadata/);
  assert.match(html, /node\.dataset\[key\]/);
  assert.doesNotMatch(html, /data-field="expires_at"/);
});

test('network objects use the fixed zone catalog', () => {
  for (const zone of ['EXT', 'OeDMZ', 'GDMZ', 'IDMZ', 'LAN', 'MGMT', 'VPN']) {
    assert.match(html, new RegExp(`<option>${zone}</option>`));
  }
  assert.match(html, /aria-label="Zone" data-field="zone" required/);
});

test('staging exposes validation, risk and deployment command results', () => {
  assert.match(html, /id="validation-results"/);
  assert.match(html, /id="risk-results"/);
  assert.match(html, /id="deployment-command-preview"/);
  assert.match(html, /admin\/stage/);
  assert.match(html, /policy:p,draft_version:draftVersion,comment:/);
});

test('reviewer diff renders structured before and after documents', () => {
  assert.match(html, /function diffDocument\(/);
  assert.match(html, /function renderPolicyChange\(/);
  assert.match(html, /<h5>Vorher<\/h5>/);
  assert.match(html, /<h5>Nachher<\/h5>/);
  assert.match(html, /change\.field_changes/);
  assert.match(html, /Geänderte Felder/);
  assert.match(html, /field\.path/);
  assert.match(html, /changes\.map\(renderPolicyChange\)/);
  assert.match(html, /x\.changes\.map\(renderPolicyChange\)/);
});

test('four-eyes workflow separates review and deployment roles', () => {
  assert.match(html, /option value="reviewer"/);
  assert.match(html, /option value="deployer"/);
  assert.match(html, /option value="developer">Developer<\/option>/);
  assert.match(html, /admin\/publish/);
  assert.match(html, /admin\/reject/);
  assert.match(html, /samePerson/);
  assert.match(html, /admin\/deploy/);
});

test('developer receives every administrative capability and is the sole four-eyes exception', () => {
  assert.match(html, /const isDeveloper=\(\)=>currentRole==='developer'/);
  assert.match(html, /canAdmin=\(\)=>currentRole==='admin'\|\|isDeveloper\(\)/);
  assert.match(html, /canEdit=\(\)=>!initialized\|\|canAdmin\(\)\|\|currentRole==='editor'/);
  assert.match(html, /canReview=\(\)=>canAdmin\(\)\|\|currentRole==='reviewer'/);
  assert.match(html, /hasDeployRole=\(\)=>canAdmin\(\)\|\|currentRole==='deployer'/);
  assert.match(html, /canDeploy=\(\)=>hasDeployRole\(\)&&!fortiGateReadOnly/);
  assert.match(html, /fourEyesBlocked=Boolean\(samePerson&&!isDeveloper\(\)\)/);
  assert.match(html, /own=!isDeveloper\(\)&&linkedPolicyRequestIsOwn\(\)/);
  assert.match(html, /!isDeveloper\(\)&&\(linkedPolicyRequestIsOwn\(\)\|\|pendingRevisionIsOwn\(\)\)/);
  assert.match(html, /\['admin','editor','reviewer','deployer','developer'\]\.includes\(currentRole\)/);
  assert.match(html, /Developer dürfen auch eigene Revisionen und Anträge entscheiden/);
});

test('operational safeguards have explicit API flows', () => {
  for (const endpoint of ['rollback', 'audit', 'where-used', 'maintenance', 'drift']) {
    assert.match(html, new RegExp(`admin\\/${endpoint}`), `${endpoint} endpoint is missing`);
  }
  assert.match(html, /admin\/ldap-sync-preview/);
  assert.doesNotMatch(html, /ldap-sync\?dry_run/);
  assert.match(html, /preview_token/);
  assert.match(html, /error\.status===409/);
  assert.match(html, /'X-Policy-Draft-Version':draftVersion/);
  assert.match(html, /result\.records\|\|result\.references/);
  assert.match(html, /result\.records\|\|result\.items/);
  assert.match(html, /plan_hash:planHash/);
  assert.match(html, /validation\.plan_hash/);
});

test('FortiGate read-only mode disables deployment but keeps drift available', () => {
  assert.match(html, /id="fortigate-access"/);
  assert.match(html, /fortiGateReadOnly=Boolean\(status\.fortigate_read_only\)/);
  assert.match(html, /fortiGateReadOnly\?'Read-only':'Deployment freigegeben'/);
  assert.match(html, /\$\('#deploy'\)\.disabled=!canDeploy\(\)/);
  assert.match(html, /\$\('#load-drift'\)\.disabled=!\(hasDeployRole\(\)\|\|canReview\(\)\)/);
});

test('maintenance and bootstrap use final security contracts', () => {
  assert.match(html, /const settings=data\.settings\|\|data/);
  assert.match(html, /function toRFC3339\(/);
  assert.match(html, /starts_at:toRFC3339/);
  assert.match(html, /type="password" autocomplete="new-password"/);
  assert.match(html, /'X-PolicyWeb-Bootstrap-Token':token/);
  assert.match(html, /bootstrap-token'\)\.value=''/);
  assert.match(html, /MKey wird per Name aufgelöst/);
  assert.match(html, /insert_before/);
  assert.match(html, /command\.create_payload/);
  assert.match(html, /effectiveCreatePayload=command\.create_payload\|\|\(upsert\?command\.payload:null\)/);
  assert.match(html, /CREATE-Zweig \(Objekt nicht vorhanden\)/);
  assert.match(html, /UPDATE-Zweig \(Objekt vorhanden\)/);
  assert.match(html, /rohes CMDB-JSON \(kein data-Envelope\)/);
  assert.match(html, /PREPARE-Zweig \(Policy nicht vorhanden; deaktiviert anlegen und positionieren\)/);
  assert.match(html, /Ausführungsphasen: 1 Objekte anlegen\/prüfen/);
  assert.match(html, /Endpoint \$\{target\.endpoint\|\|'–'\}/);
  assert.match(html, /requestPart,dynamicMKey,anchor,command\.command/);
});
