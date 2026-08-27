import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

async function loadExtDefinition(relativePath, extraContext = {}) {
  let definition;
  const context = {
    JSON,
    console,
    Ext: {
      define(name, value) {
        definition = value;
      },
      merge(...values) {
        return Object.assign(...values);
      },
      apply(target, value) {
        return Object.assign(target, value);
      },
    },
    ...extraContext,
  };
  const source = await readFile(join(repositoryRoot, relativePath), 'utf8');
  vm.runInNewContext(source, context, { filename: relativePath });
  return { definition, source };
}

test('service user button targets its card by itemId and refreshes users', async () => {
  const { definition } = await loadExtDefinition(
    join('app', 'controller', 'Service.js'),
    {
      appstate: {
        getOwner: () => 'VB1',
        getHistory: () => 'p1',
        getNetworks: () => '',
      },
    },
  );

  const detailsCard = { itemId: 'service-details-card' };
  const usersCard = { itemId: 'service-users-card' };
  const card = {
    layout: {
      activeItem: detailsCard,
      setActiveItem(item) {
        this.activeItem = item;
      },
    },
    getComponent(itemId) {
      return itemId === 'service-users-card' ? usersCard : detailsCard;
    },
  };
  let usersLoaded = 0;
  const checkboxCalls = [];
  const controller = {
    ...definition,
    getDetailsAndUserView: () => card,
    getCurrentRelation: () => 'owner',
    enableAndDisableCheckboxes(enable, disable) {
      checkboxCalls.push({ enable, disable });
    },
    enableCheckboxes() {},
    loadSelectedServiceUsers() {
      usersLoaded += 1;
    },
  };

  definition.onServiceDetailsButtonClick.call(controller, {
    serviceCardItemId: 'service-users-card',
    pressed: true,
  });

  assert.equal(card.layout.activeItem, usersCard);
  assert.equal(usersLoaded, 1);
  assert.equal(checkboxCalls.length, 1);
  assert.equal(Object.keys(checkboxCalls[0].disable).join(','), 'display_property');
});

function fakeUsersStore() {
  const proxy = { extraParams: {} };
  return {
    loading: false,
    loads: [],
    removeCount: 0,
    getProxy: () => proxy,
    isLoading() {
      return this.loading;
    },
    removeAll() {
      this.removeCount += 1;
    },
    load(options) {
      this.loading = true;
      this.loads.push(options);
    },
    finish(success = true) {
      const options = this.loads.at(-1);
      this.loading = false;
      options.callback.call(options.scope, [], {}, success);
    },
  };
}

test('service user loads carry service context and serialize changed selections', async () => {
  const appstate = {
    getOwner: () => 'VB1',
    getHistory: () => 'p42',
    getNetworks: () => 'network:clients',
  };
  const { definition } = await loadExtDefinition(
    join('app', 'controller', 'Service.js'),
    { appstate },
  );
  const store = fakeUsersStore();
  let selectedService = 'web';
  let emailClears = 0;
  const controller = {
    ...definition,
    getUsersStore: () => store,
    getSelectedServiceName: () => selectedService,
    getServiceDataParams: () => ({ display_property: 'ip' }),
    getUserDetailEmails: () => ({ clear: () => { emailClears += 1; } }),
  };

  definition.loadSelectedServiceUsers.call(controller);
  assert.equal(store.loads.length, 1);
  assert.deepEqual(
    { ...store.loads[0].params },
    {
      display_property: 'ip',
      service: 'web',
      active_owner: 'VB1',
      history: 'p42',
      chosen_networks: 'network:clients',
    },
  );

  // A second selection is queued until the active request finishes. ExtJS 4
  // otherwise allows the older response to overwrite the newer one.
  selectedService = 'dns';
  definition.loadSelectedServiceUsers.call(controller);
  assert.equal(store.loads.length, 1);
  assert.equal(store.policyWebQueuedLoad.name, 'dns');
  assert.ok(emailClears > 0);

  store.finish();
  assert.equal(store.loads.length, 2);
  assert.equal(store.loads[1].params.service, 'dns');
  store.finish();

  // Reopening the already loaded card reuses the current result.
  definition.loadSelectedServiceUsers.call(controller);
  assert.equal(store.loads.length, 2);
});

test('service user model displays an FQDN when no IP address exists', async () => {
  const { definition } = await loadExtDefinition(
    join('app', 'model', 'User.js'),
  );
  const addressField = definition.fields.find((field) => field.name === 'ip');

  assert.equal(
    addressField.convert('', { raw: { fqdn: 'api.example.org' } }),
    'api.example.org',
  );
  assert.equal(
    addressField.convert('192.0.2.8', { raw: { fqdn: 'api.example.org' } }),
    '192.0.2.8',
  );
});

test('service user cards and empty state have explicit contracts', async () => {
  const serviceView = await readFile(
    join(repositoryRoot, 'app', 'view', 'Service.js'),
    'utf8',
  );
  const usersGrid = await readFile(
    join(repositoryRoot, 'app', 'view', 'panel', 'grid', 'Users.js'),
    'utf8',
  );

  assert.match(serviceView, /serviceCardItemId:\s*'service-details-card'/);
  assert.match(serviceView, /serviceCardItemId:\s*'service-users-card'/);
  assert.match(serviceView, /itemId:\s*'service-details-card'/);
  assert.match(serviceView, /itemId:\s*'service-users-card'/);
  assert.match(usersGrid, /deferEmptyText\s*:\s*false/);
  assert.match(usersGrid, /keine Benutzerobjekte/);
  assert.match(usersGrid, /IP-Adresse \/ FQDN/);
});
