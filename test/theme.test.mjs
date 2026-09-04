import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const themeSource = await readFile(
  join(repositoryRoot, 'resources', 'js', 'theme.js'),
  'utf8',
);

function fakeElement(initialAttributes = {}) {
  const attributes = new Map(Object.entries(initialAttributes));
  const listeners = new Map();

  return {
    textContent: '',
    setAttribute(name, value) {
      attributes.set(name, String(value));
    },
    getAttribute(name) {
      return attributes.has(name) ? attributes.get(name) : null;
    },
    querySelector() {
      return null;
    },
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
    click() {
      listeners.get('click')?.({ type: 'click', target: this });
    },
  };
}

function loadTheme({
  storedTheme,
  systemDark = false,
  storageThrows = false,
  readyState = 'complete',
} = {}) {
  const values = new Map();
  if (storedTheme !== undefined) {
    values.set('policyweb-theme', storedTheme);
  }

  const html = fakeElement();
  const body = fakeElement();
  const toggle = fakeElement({ 'data-policyweb-theme-toggle': '' });
  const documentListeners = new Map();
  const windowListeners = new Map();
  const mediaListeners = new Set();
  const mediaQuery = {
    matches: systemDark,
    addEventListener(type, listener) {
      if (type === 'change') mediaListeners.add(listener);
    },
    emit(matches) {
      this.matches = matches;
      for (const listener of mediaListeners) listener({ matches });
    },
  };
  const localStorage = {
    getItem(key) {
      if (storageThrows) throw new Error('storage unavailable');
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      if (storageThrows) throw new Error('storage unavailable');
      values.set(key, String(value));
    },
    removeItem(key) {
      if (storageThrows) throw new Error('storage unavailable');
      values.delete(key);
    },
  };
  const document = {
    documentElement: html,
    body,
    readyState,
    querySelectorAll(selector) {
      assert.match(selector, /policyweb-theme-toggle|pw-theme-toggle/);
      return [toggle];
    },
    addEventListener(type, listener) {
      documentListeners.set(type, listener);
    },
  };
  const window = {
    localStorage,
    matchMedia(query) {
      assert.equal(query, '(prefers-color-scheme: dark)');
      return mediaQuery;
    },
    addEventListener(type, listener) {
      windowListeners.set(type, listener);
    },
  };

  vm.runInNewContext(themeSource, { document, window });

  return {
    api: window.PolicyWebTheme,
    body,
    html,
    mediaQuery,
    storage: values,
    toggle,
    fireDOMContentLoaded() {
      documentListeners.get('DOMContentLoaded')?.();
    },
    emitStorage(newValue) {
      if (newValue === null) values.delete('policyweb-theme');
      else values.set('policyweb-theme', newValue);
      windowListeners.get('storage')?.({
        key: 'policyweb-theme',
        newValue,
      });
    },
  };
}

test('stored preference overrides the system and initializes the toggle', () => {
  const theme = loadTheme({ storedTheme: 'light', systemDark: true });

  assert.equal(theme.api.storageKey, 'policyweb-theme');
  assert.equal(theme.api.get(), 'light');
  assert.equal(theme.html.getAttribute('data-theme'), 'light');
  assert.equal(theme.body.getAttribute('data-theme'), 'light');
  assert.equal(theme.toggle.getAttribute('data-theme-current'), 'light');
  assert.equal(theme.toggle.getAttribute('aria-pressed'), null);
  assert.equal(theme.toggle.getAttribute('aria-label'), 'Dark Mode aktivieren');
  assert.equal(theme.toggle.textContent, 'Dark Mode');
});

test('toggle click updates DOM, button state, and persistent preference', () => {
  const theme = loadTheme({ systemDark: false });

  theme.toggle.click();
  assert.equal(theme.api.get(), 'dark');
  assert.equal(theme.storage.get('policyweb-theme'), 'dark');
  assert.equal(theme.html.getAttribute('data-theme'), 'dark');
  assert.equal(theme.toggle.getAttribute('data-theme-current'), 'dark');
  assert.equal(theme.toggle.getAttribute('aria-pressed'), null);
  assert.equal(theme.toggle.getAttribute('title'), 'Light Mode aktivieren');
  assert.equal(theme.toggle.textContent, 'Light Mode');

  theme.toggle.click();
  assert.equal(theme.api.get(), 'light');
  assert.equal(theme.storage.get('policyweb-theme'), 'light');
  assert.equal(theme.toggle.getAttribute('data-theme-current'), 'light');
});

test('toggle binding waits for DOMContentLoaded when the document is loading', () => {
  const theme = loadTheme({ readyState: 'loading', systemDark: true });

  assert.equal(theme.toggle.getAttribute('data-theme-current'), null);
  theme.fireDOMContentLoaded();
  assert.equal(theme.toggle.getAttribute('data-theme-current'), 'dark');
  assert.equal(theme.toggle.textContent, 'Light Mode');

  theme.toggle.click();
  assert.equal(theme.api.get(), 'light');
});

test('system preference remains live until the user chooses a theme', () => {
  const theme = loadTheme({ systemDark: false });

  theme.mediaQuery.emit(true);
  assert.equal(theme.api.get(), 'dark');
  assert.equal(theme.toggle.getAttribute('data-theme-current'), 'dark');

  theme.api.set('light');
  theme.mediaQuery.emit(true);
  assert.equal(theme.api.get(), 'light');

  theme.api.useSystemPreference();
  assert.equal(theme.storage.has('policyweb-theme'), false);
  assert.equal(theme.api.get(), 'dark');
});

test('storage changes synchronize theme instances and invalid values use the system', () => {
  const theme = loadTheme({ systemDark: true, storedTheme: 'light' });

  theme.emitStorage('dark');
  assert.equal(theme.api.get(), 'dark');
  assert.equal(theme.toggle.textContent, 'Light Mode');

  theme.emitStorage('invalid');
  assert.equal(theme.api.get(), 'dark');

  theme.mediaQuery.emit(false);
  theme.emitStorage(null);
  assert.equal(theme.api.get(), 'light');
  assert.equal(theme.toggle.textContent, 'Dark Mode');
});

test('theme still switches visually when localStorage is unavailable', () => {
  const theme = loadTheme({ systemDark: true, storageThrows: true });

  assert.equal(theme.api.get(), 'dark');
  theme.toggle.click();
  assert.equal(theme.api.get(), 'light');
  assert.equal(theme.html.getAttribute('data-theme'), 'light');
});

test('invalid programmatic themes are rejected', () => {
  const theme = loadTheme();
  assert.throws(() => theme.api.set('sepia'), /light.*dark/);
});

test('static pages load the shared theme assets', async (t) => {
	const pages = ['admin.html', 'devices.html', 'requests.html', 'index.html', 'start.html', 'passwd.html'];

  for (const page of pages) {
    await t.test(page, async () => {
      const html = await readFile(join(repositoryRoot, page), 'utf8');
      assert.match(html, /resources\/css\/theme-static\.css/);
      assert.match(html, /resources\/js\/theme\.js/);
    });
	}
});

test('ExtJS application loads the theme runtime and its dedicated overlay', async () => {
	const html = await readFile(join(repositoryRoot, 'app.html'), 'utf8');
	assert.match(html, /resources\/js\/theme\.js/);
	assert.match(html, /resources\/css\/dark-theme\.css/);
	assert.doesNotMatch(html, /resources\/css\/theme-static\.css/);

	const controller = await readFile(
		join(repositoryRoot, 'app', 'controller', 'Main.js'),
		'utf8',
	);
	assert.match(controller, /PolicyWebTheme\.toggle\(\)/);
	assert.match(controller, /PolicyWebTheme\.onChange/);

	const adminView = await readFile(
		join(repositoryRoot, 'app', 'view', 'Admin.js'),
		'utf8',
	);
	assert.match(adminView, /pw-admin-frame/);
	assert.doesNotMatch(adminView, /background\s*:\s*#f4f7fa/i);

	const devicesView = await readFile(
		join(repositoryRoot, 'app', 'view', 'Devices.js'),
		'utf8',
	);
	assert.match(devicesView, /pw-devices-frame/);
	assert.match(devicesView, /devices\.html\?embedded=1/);
});

test('standalone backend templates load the shared theme assets', async (t) => {
  const templateDirectory = join(repositoryRoot, 'go', 'pkg', 'backend', 'html-templates');
  const templates = ['error', 'show_passwd', 'verify_confirm', 'verify_fail', 'verify_ok'];

  for (const template of templates) {
    await t.test(template, async () => {
      const html = await readFile(join(templateDirectory, template), 'utf8');
      assert.match(html, /resources\/css\/theme-static\.css/);
      assert.match(html, /resources\/js\/theme\.js/);
    });
  }
});

test('about dialog does not force the former light-theme text color', async () => {
  const html = await readFile(
    join(repositoryRoot, 'go', 'pkg', 'backend', 'html-templates', 'about_info'),
    'utf8',
  );
  assert.doesNotMatch(html, /color\s*:\s*#263746/i);
});

test('shared CSS defines dark colors and accessible toggle state', async () => {
  const css = await readFile(
    join(repositoryRoot, 'resources', 'css', 'theme-static.css'),
    'utf8',
  );
  assert.match(css, /:root\[data-theme=["']dark["']\]/);
  assert.match(css, /color-scheme\s*:\s*dark/);
	assert.match(css, /\.pw-theme-toggle\[data-theme-current=["']dark["']\]/);

	const extCSS = await readFile(
		join(repositoryRoot, 'resources', 'css', 'dark-theme.css'),
		'utf8',
	);
	assert.match(extCSS, /html\[data-theme=["']dark["']\]/);
	assert.match(extCSS, /color-scheme\s*:\s*dark/);
	assert.match(extCSS, /html\[data-theme=["']dark["']\]\s+\.pw-admin-frame/);
	assert.match(extCSS, /html\[data-theme=["']dark["']\]\s+\.pw-devices-frame/);
	assert.match(extCSS, /html\[data-theme=["']dark["']\]\s+\.x-form-arrow-trigger/);
	assert.match(extCSS, /html\[data-theme=["']dark["']\]\s+\.x-window-default/);
});

test('native and ExtJS checkboxes keep theme-specific geometry and states', async () => {
  const admin = await readFile(join(repositoryRoot, 'admin.html'), 'utf8');
  assert.match(admin, /class=["']read-all-toggle["']/);
  assert.match(admin, /data-field=["']read_all["']\s+type=["']checkbox["']/);
  assert.match(admin, /input:not\(\[type=["']checkbox["']\]\):not\(\[type=["']radio["']\]\)/);

  const staticCSS = await readFile(
    join(repositoryRoot, 'resources', 'css', 'theme-static.css'),
    'utf8',
  );
  assert.match(staticCSS, /input\[type=["']checkbox["']\]/);
  assert.match(staticCSS, /accent-color\s*:\s*var\(--pw-accent\)/);
  assert.match(staticCSS, /block-size\s*:\s*16px/);
  assert.match(staticCSS, /inline-size\s*:\s*16px/);
  assert.match(staticCSS, /min-width\s*:\s*16px/);
  assert.match(staticCSS, /padding\s*:\s*0/);

  const extCSS = await readFile(
    join(repositoryRoot, 'resources', 'css', 'dark-theme.css'),
    'utf8',
  );
  const genericFormRule = extCSS.indexOf('html[data-theme="dark"] .x-form-field,');
  const checkboxRule = extCSS.indexOf('html[data-theme="dark"] .x-form-checkbox,');
  assert.ok(genericFormRule >= 0, 'generic ExtJS form-field rule must exist');
  assert.ok(checkboxRule > genericFormRule, 'checkbox override must follow the generic form-field rule');
  assert.match(extCSS, /\.x-form-cb-checked\s+\.x-form-checkbox/);
  assert.match(extCSS, /\.x-form-checkbox-focus/);
  assert.match(extCSS, /\.x-item-disabled\s+\.x-form-checkbox/);
  assert.match(extCSS, /\.x-grid-row-selected\s+\.x-grid-row-checker/);

  const diffView = await readFile(
    join(repositoryRoot, 'app', 'view', 'tree', 'Diff.js'),
    'utf8',
  );
  assert.match(diffView, /aria-label=["']Diff per Mail senden["']/);
});
