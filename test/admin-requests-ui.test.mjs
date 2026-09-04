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

const requestHelperNames = [
  'requestPayload',
  'requestFirst',
  'requestDisplayValue',
  'requestID',
  'requestRevision',
  'requestPolicyID',
  'requestDecision',
  'requestView',
  'requestStatusClass',
  'requestIsPreStage',
  'requestCanReject',
  'requestStageActor',
  'policyRequestMutationBody',
  'requestCardHTML',
];
const requestHelperSource = requestHelperNames.map(functionLine).join('\n');

function escapeHTML(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function requestContext(role, currentUser = 'operator@example.net') {
  const context = {
    currentRole: role,
    currentUser,
    requestActionPending: false,
    requestListStale: false,
    escapeHTML,
    isDeveloper: () => role === 'developer',
    canEdit: () => ['admin', 'editor', 'developer'].includes(role),
    canReview: () => ['admin', 'reviewer', 'developer'].includes(role),
    hasDeployRole: () => ['admin', 'deployer', 'developer'].includes(role),
  };
  vm.createContext(context);
  vm.runInContext(requestHelperSource, context);
  return context;
}

function submittedRequest(overrides = {}) {
  return {
    id: 'req-1',
    revision: 4,
    type: 'rule_change',
    requester: 'requester@example.net',
    active_owner: 'VB1',
    base_version: 'p-base',
    payload: {
      service: 'web',
      stable_rule_id: 'rule-stable-1',
      operation: 'add',
      field: 'sources',
      values: ['network:clients'],
    },
    reason: 'Fachliche Begründung',
    status: 'submitted',
    created_at: '2026-08-30T12:00:00Z',
    ...overrides,
  };
}

test('admin exposes an Antragswesen tab with the complete review record', () => {
  assert.match(html, /data-tab="requests">Antragswesen/);
  assert.match(html, /<section id="requests">/);
  assert.match(html, /id="request-list"/);
  assert.match(html, /id="reload-requests"/);
  assert.match(html, /id="load-more-requests"/);
  assert.match(html, /id="request-page-status"/);
  for (const label of [
    'Antragsteller', 'Zeitpunkt', 'Typ', 'Dienst', 'Stabile Regel-ID',
    'Operation', 'Feld', 'Werte', 'Begründung', 'Basisversion', 'Status',
    'Policy-ID', 'Entscheidung',
  ]) {
    assert.match(adminScript, new RegExp(`>${label}<`), `${label} is missing`);
  }
});

test('request rendering escapes every server-controlled value and uses only a numeric DOM index', () => {
  const poison = '<img src=x onerror="globalThis.pwned=true">';
  const context = requestContext('admin', 'reviewer@example.net');
  const card = context.requestCardHTML(submittedRequest({
    id: poison,
    type: poison,
    requester: poison,
    active_owner: poison,
    base_version: poison,
    reason: poison,
    created_at: poison,
    payload: {
      service: poison,
      stable_rule_id: poison,
      operation: poison,
      field: poison,
      values: [poison, { nested: poison }],
    },
  }), 0);

  assert.doesNotMatch(card, /<img/i);
  assert.doesNotMatch(card, /data-(?:id|revision|policy-id)=/i);
  assert.match(card, /data-request-index="0"/);
  assert.match(card, /&lt;img src=x onerror=&quot;globalThis\.pwned=true&quot;&gt;/);
});

test('request actions follow operational roles and exempt only developer from four-eyes separation', () => {
  const request = submittedRequest();

  const editorCard = requestContext('editor').requestCardHTML(request, 0);
  assert.match(editorCard, /data-request-action="stage"/);
  assert.doesNotMatch(editorCard, /data-request-action="reject"/);

  const reviewerCard = requestContext('reviewer').requestCardHTML(request, 0);
  assert.doesNotMatch(reviewerCard, /data-request-action="stage"/);
  assert.match(reviewerCard, /data-request-action="reject"/);

  const ownCard = requestContext('reviewer', request.requester).requestCardHTML(request, 0);
  assert.doesNotMatch(ownCard, /data-request-action="reject"/);
  assert.match(ownCard, /Eigene Anträge dürfen im Vier-Augen-Prinzip nicht abgelehnt oder genehmigt werden/);

  const adminCard = requestContext('admin').requestCardHTML(request, 0);
  assert.match(adminCard, /data-request-action="stage"/);
  assert.match(adminCard, /data-request-action="reject"/);

  const deployedRoleCard = requestContext('deployer').requestCardHTML(submittedRequest({
    status: 'staged',
    revision_version: 'p-reviewed',
  }), 0);
  assert.match(deployedRoleCard, /data-request-action="open-revision"/);
  assert.doesNotMatch(deployedRoleCard, /data-request-action="(?:stage|reject)"/);

  for (const status of ['staged', 'conflict']) {
    const reviewCard = requestContext('reviewer').requestCardHTML(submittedRequest({
      status,
      revision_version: status === 'staged' ? 'p-reviewed' : '',
    }), 0);
    assert.match(reviewCard, /data-request-action="reject"/, `${status} request cannot be rejected`);
  }

  const ownStagedCard = requestContext('reviewer', 'stager@example.net').requestCardHTML(submittedRequest({
    status: 'staged',
    revision_version: 'p-staged',
    events: [{ action: 'request.staged', actor: 'stager@example.net' }],
  }), 0);
  assert.doesNotMatch(ownStagedCard, /data-request-action="reject"/);
  assert.match(ownStagedCard, /eigene gestagte Revision darf nicht selbst abgelehnt werden/i);

  const developerOwnCard = requestContext('developer', request.requester).requestCardHTML(request, 0);
  assert.match(developerOwnCard, /data-request-action="stage"/);
  assert.match(developerOwnCard, /data-request-action="reject"/);
  assert.doesNotMatch(developerOwnCard, /Vier-Augen-Prinzip/);

  const developerOwnStagedCard = requestContext('developer', 'stager@example.net').requestCardHTML(submittedRequest({
    status: 'staged',
    revision_version: 'p-developer',
    requester: 'stager@example.net',
    events: [{ action: 'request.staged', actor: 'stager@example.net' }],
  }), 0);
  assert.match(developerOwnStagedCard, /data-request-action="reject"/);
  assert.match(developerOwnStagedCard, /data-request-action="open-revision"/);
  assert.doesNotMatch(developerOwnStagedCard, /eigene gestagte Revision/i);
});

test('request decisions use the latest approval, rejection or deployment event', () => {
  const context = requestContext('reviewer');
  const view = context.requestView(submittedRequest({
    status: 'deployed',
    events: [
      { action: 'request.approved', actor: 'reviewer@example.net' },
      { action: 'request.deployed', actor: 'deployer@example.net', comment: 'Rollout erfolgreich' },
    ],
  }));
  assert.equal(view.decision, 'Ausgerollt · von deployer@example.net · Rollout erfolgreich');
});

test('request mutations bind the exact ID and optimistic revision', () => {
  const context = requestContext('admin');
  const item = submittedRequest({ id: 'req-cas', revision: 17 });

  assert.deepEqual(
    JSON.parse(JSON.stringify(context.policyRequestMutationBody(item))),
    { id: 'req-cas', revision: 17 },
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.policyRequestMutationBody(item, '  nicht ausreichend  '))),
    { id: 'req-cas', revision: 17, comment: 'nicht ausreichend' },
  );

  const stageSource = functionLine('stagePolicyRequest');
  const rejectSource = functionLine('rejectPolicyRequest');
  assert.match(stageSource, /admin\/requests\/stage/);
  assert.match(rejectSource, /admin\/requests\/reject/);
  assert.match(stageSource, /JSON\.stringify\(body\)/);
  assert.match(rejectSource, /JSON\.stringify\(body\)/);
  assert.match(rejectSource, /requestCanReject\(item\)/);
  assert.match(rejectSource, /requestStageActor\(item\)/);
  assert.match(rejectSource, /!isDeveloper\(\)/);
  assert.doesNotMatch(rejectSource, /requestIsPreStage\(item\)/);
});

test('request loading, staging and workflow refresh use the final API contracts', () => {
  const loadSource = functionLine('loadRequests');
  const stageSource = functionLine('stagePolicyRequest');
  const openSource = functionLine('openPolicyRequestRevision');

  assert.match(loadSource, /backend6\/admin\/requests/);
  assert.match(loadSource, /\?limit=50/);
  assert.match(loadSource, /pagination\.next_cursor/);
  assert.match(loadSource, /append\?requestNextCursor/);
  assert.match(loadSource, /new Map\(requestItems\.map/);
  assert.match(loadSource, /Array\.isArray\(result\.records\)/);
  assert.match(loadSource, /Array\.isArray\(result\.items\)/);
  assert.match(stageSource, /renderStageResult\(result\)/);
  assert.match(stageSource, /mergeStagedRequestRevision\(result\)/);
  assert.match(stageSource, /refreshRequestsAfterMutation\(\)/);
  assert.match(openSource, /openRevision\(policyID\)/);

  for (const workflowAction of ['approve', 'reject', 'deploy']) {
    assert.match(functionLine(workflowAction), /refreshRequestsAfterMutation\(\)/, `${workflowAction} does not refresh requests`);
  }
  assert.match(adminScript, /button\.dataset\.tab==='requests'\)loadRequests\(\)/);
  assert.match(adminScript, /loadRequests\(true,true\)/);
  assert.match(adminScript, /linkedPolicyRequestIsOwn\(\)/);
  assert.match(adminScript, /applyLinkedRequestFourEyes\(\)/);
  assert.match(functionLine('approve'), /linkedPolicyRequestIsOwn\(\)/);
  assert.match(functionLine('approve'), /!isDeveloper\(\)/);
  assert.match(functionLine('approve'), /pendingRevisionIsOwn\(\)/);
  assert.match(functionLine('reject'), /!isDeveloper\(\)/);
  assert.match(functionLine('reject'), /pendingRevisionIsOwn\(\)/);
  assert.match(functionLine('linkedPolicyRequestIsOwn'), /pendingRequestRequester/);
  assert.match(adminScript, /pendingRequestRequester=requestFirst\(result\.requester,result\.requested_by\)/);
});
