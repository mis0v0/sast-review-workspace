// Guards that routine browser tests cannot write committed evidence, and that
// scripts/capture-browser-evidence.mjs promotes only a complete, valid,
// successful run without touching anyone's uncommitted docs/assets changes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const captureScript = join(frontend, 'scripts', 'capture-browser-evidence.mjs');
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);

test('browser tests reach committed evidence only through the evidence helper', async () => {
  const directory = join(frontend, 'browser-tests');
  const offenders = [];
  for (const name of await readdir(directory)) {
    if (name === 'evidence.ts' || !name.endsWith('.ts')) continue;
    const source = await readFile(join(directory, name), 'utf8');
    if (/docs\/assets|\.\.\/docs\b/.test(source)) offenders.push(name);
  }
  assert.deepEqual(offenders, []);
});

function git(cwd, ...args) {
  const result = spawnSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

// A throwaway repository with the same layout: frontend/scripts and docs/assets.
async function repository(t) {
  const root = await mkdtemp(join(tmpdir(), 'evidence-capture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'frontend', 'scripts'), { recursive: true });
  await copyFile(captureScript, join(root, 'frontend', 'scripts', 'capture-browser-evidence.mjs'));
  await mkdir(join(root, 'docs', 'assets', 'ui'), { recursive: true });
  await writeFile(join(root, 'docs', 'assets', 'ui', 'old.png'), PNG);
  await writeFile(join(root, '.gitignore'), 'frontend/test-results/\n');
  git(root, 'init', '-q');
  git(root, 'add', '.');
  git(root, 'commit', '-q', '-m', 'init');
  return root;
}

// Runs the capture script with a fake "test command": a Node snippet run in frontend/.
function capture(root, snippet) {
  return spawnSync(process.execPath, [join(root, 'frontend', 'scripts', 'capture-browser-evidence.mjs'), '--', process.execPath, '-e', snippet], {
    cwd: root, encoding: 'utf8',
  });
}

const stage = (files, exitCode = 0) => `
  const fs = require('node:fs'); const path = require('node:path');
  for (const [name, hex] of ${JSON.stringify(Object.entries(files).map(([name, data]) => [name, Buffer.from(data).toString('hex')]))}) {
    const target = path.join('test-results', 'evidence', name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, Buffer.from(hex, 'hex'));
  }
  process.exit(${exitCode});`;

const status = (root) => git(root, 'status', '--porcelain', '--untracked-files=all');

test('a successful run promotes exactly the staged evidence', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'ui/old.png': Buffer.concat([PNG, Buffer.from([9])]), 'ui/new.json': '{"a":1}' }));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(status(root), ' M docs/assets/ui/old.png\n?? docs/assets/ui/new.json\n');
  assert.equal(await readFile(join(root, 'docs', 'assets', 'ui', 'new.json'), 'utf8'), '{"a":1}');
});

test('a failing test command promotes nothing', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'ui/new.png': PNG }, 1));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /did not succeed/);
  assert.equal(status(root), '');
});

test('one invalid artifact blocks the whole promotion', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'ui/a.png': PNG, 'ui/b.png': 'not an image', 'ui/c.json': '{' }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /b\.png: not a PNG image/);
  assert.match(result.stderr, /c\.json: invalid JSON/);
  assert.equal(status(root), '');
});

test('uncommitted docs/assets changes stop the capture before anything runs', async (t) => {
  const root = await repository(t);
  const edited = Buffer.concat([PNG, Buffer.from('user edit')]);
  await writeFile(join(root, 'docs', 'assets', 'ui', 'old.png'), edited);
  const result = capture(root, `require('node:fs').writeFileSync('ran', ''); ${stage({ 'ui/old.png': PNG })}`);
  assert.equal(result.status, 2);
  assert.deepEqual(await readFile(join(root, 'docs', 'assets', 'ui', 'old.png')), edited);
  await assert.rejects(readFile(join(root, 'frontend', 'ran')));
});

test('evidence left from an earlier run is never promoted', async (t) => {
  const root = await repository(t);
  await mkdir(join(root, 'frontend', 'test-results', 'evidence', 'ui'), { recursive: true });
  await writeFile(join(root, 'frontend', 'test-results', 'evidence', 'ui', 'stale.png'), PNG);
  const result = capture(root, stage({ 'ui/fresh.png': PNG }));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(status(root), '?? docs/assets/ui/fresh.png\n');
});

test('a run that writes docs/assets directly fails and keeps that change for review', async (t) => {
  const root = await repository(t);
  const result = capture(root, `require('node:fs').writeFileSync('../docs/assets/ui/old.png', 'leak'); ${stage({ 'ui/new.png': PNG })}`);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /wrote into docs\/assets directly/);
  assert.equal(status(root), ' M docs/assets/ui/old.png\n');
  assert.equal(await readFile(join(root, 'docs', 'assets', 'ui', 'old.png'), 'utf8'), 'leak');
});

test('symbolic links and empty runs are refused', async (t) => {
  const root = await repository(t);
  const linked = capture(root, `${stage({ 'ui/a.png': PNG }).replace(/process\.exit\(0\);$/, '')}
    fs.symlinkSync('/etc/hosts', path.join('test-results', 'evidence', 'ui', 'link.png')); process.exit(0);`);
  assert.equal(linked.status, 1);
  assert.match(linked.stderr, /link\.png: not a regular file/);
  const empty = capture(root, 'process.exit(0)');
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /produced no evidence/);
  assert.equal(status(root), '');
});
