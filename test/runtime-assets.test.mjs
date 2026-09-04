import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

async function filesBelow(root) {
  const files = [];

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(relative(root, path).replaceAll('\\', '/'));
    }
  }

  await visit(root);
  return files.sort();
}

test('the Silk icon bundle contains exactly the referenced runtime assets', async () => {
  const sources = await Promise.all([
    readFile(join(repositoryRoot, 'resources', 'css', 'icons.css'), 'utf8'),
    readFile(join(repositoryRoot, 'html', 'task_mail_info_text'), 'utf8'),
  ]);
  const referenced = [...new Set(sources.flatMap((source) =>
    [...source.matchAll(/\/silk-icons\/([A-Za-z0-9_.-]+\.png)/g)]
      .map((match) => match[1]),
  ))].sort();
  const bundled = (await readdir(join(repositoryRoot, 'htdocs', 'silk-icons')))
    .filter((name) => name.endsWith('.png'))
    .sort();

  assert.deepEqual(bundled, referenced);
});

test('the ExtJS vendor tree contains only the production runtime closure', async () => {
  const extRoot = join(repositoryRoot, 'htdocs', 'extjs4');
  const classicCSS = await readFile(
    join(extRoot, 'resources', 'ext-theme-classic', 'ext-theme-classic-all.css'),
    'utf8',
  );
  const classicImages = [...classicCSS.matchAll(/url\((?:["']?)(images\/[^)"']+)(?:["']?)\)/g)]
    .map((match) => `resources/ext-theme-classic/${match[1]}`);
  const expected = [...new Set([
    'ext-all.js',
    'license.txt',
    'locale/ext-lang-de.js',
    'resources/css/ext-all.css',
    'resources/ext-theme-classic/ext-theme-classic-all.css',
    'resources/themes/images/default/tree/s.gif',
    ...classicImages,
  ])].sort();

  assert.deepEqual(await filesBelow(extRoot), expected);
});
