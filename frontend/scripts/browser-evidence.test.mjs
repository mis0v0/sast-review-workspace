// Guards that routine browser tests cannot write committed evidence, and that
// scripts/capture-browser-evidence.mjs publishes only a complete, valid,
// successful run, all or nothing, without touching anyone's uncommitted
// docs/assets changes.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(frontend, '..');
const captureScript = join(frontend, 'scripts', 'capture-browser-evidence.mjs');
const MANIFEST = 'browser-evidence-manifest.json';
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

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

test('committed evidence matches its provenance manifest', async (t) => {
  let manifest;
  try { manifest = JSON.parse(await readFile(join(repositoryRoot, 'docs', 'assets', MANIFEST), 'utf8')); } catch (error) {
    if (error.code === 'ENOENT') return t.skip('no evidence has been published through the capture script yet');
    throw error;
  }
  const mismatched = [];
  for (const [path, entry] of Object.entries(manifest)) {
    const bytes = await readFile(join(repositoryRoot, 'docs', 'assets', path)).catch(() => null);
    if (bytes === null || sha256(bytes) !== entry.sha256) mismatched.push(path);
  }
  assert.deepEqual(mismatched, [], 'these files were changed or removed after capture');
});

function git(cwd, ...args) {
  const result = spawnSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

// A throwaway repository with the same layout: frontend/scripts and docs/assets.
async function repository(t) {
  const root = await mkdtemp(join(tmpdir(), 'evidence-capture-'));
  t.after(async () => {
    spawnSync('chflags', ['-R', 'nouchg', root]);
    await chmod(join(root, 'docs', 'assets', 'b'), 0o755).catch(() => {});
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(join(root, 'frontend', 'scripts'), { recursive: true });
  await copyFile(captureScript, join(root, 'frontend', 'scripts', 'capture-browser-evidence.mjs'));
  for (const directory of ['a', 'b']) {
    await mkdir(join(root, 'docs', 'assets', directory), { recursive: true });
    await writeFile(join(root, 'docs', 'assets', directory, 'old.png'), PNG);
  }
  await writeFile(join(root, '.gitignore'), 'frontend/test-results/\n');
  git(root, 'init', '-q');
  git(root, 'add', '.');
  git(root, 'commit', '-q', '-m', 'init');
  return root;
}

const stage = (files, exitCode = 0) => `
  const fs = require('node:fs'); const path = require('node:path');
  for (const [name, hex] of ${JSON.stringify(Object.entries(files).map(([name, data]) => [name, Buffer.from(data).toString('hex')]))}) {
    const target = path.join('test-results', 'evidence', name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, Buffer.from(hex, 'hex'));
  }
  process.exit(${exitCode});`;

const captureArgs = (root, snippet) => [join(root, 'frontend', 'scripts', 'capture-browser-evidence.mjs'), '--', process.execPath, '-e', snippet];

// Runs the capture script with a fake "test command": a Node snippet run in frontend/.
function capture(root, snippet, cwd = root) {
  return spawnSync(process.execPath, captureArgs(root, snippet), { cwd, encoding: 'utf8' });
}

function captureAsync(t, root, snippet) {
  const child = spawn(process.execPath, captureArgs(root, snippet), { cwd: root, stdio: ['ignore', 'ignore', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const done = new Promise((resolvePromise) => child.on('close', (status) => resolvePromise({ status, stderr })));
  return { child, done };
}

const status = (root) => git(root, 'status', '--porcelain', '--untracked-files=all');
const lockPath = (root) => resolve(root, git(root, 'rev-parse', '--git-path', 'evidence-capture.lock').trim());
const leftovers = async (root) => (await readdir(join(root, 'docs'), { recursive: true })).filter((name) => name.includes('.evidence-'));
const manifest = async (root) => JSON.parse(await readFile(join(root, 'docs', 'assets', MANIFEST), 'utf8'));
const changed = Buffer.concat([PNG, Buffer.from([9])]);

test('a successful run publishes exactly the staged evidence with its provenance', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'a/old.png': changed, 'a/new.json': '{"a":1}' }), tmpdir());
  assert.equal(result.status, 0, result.stderr);
  assert.equal(status(root), ` M docs/assets/a/old.png\n?? docs/assets/a/new.json\n?? docs/assets/${MANIFEST}\n`);
  assert.equal(await readFile(join(root, 'docs', 'assets', 'a', 'new.json'), 'utf8'), '{"a":1}');
  const recorded = await manifest(root);
  assert.deepEqual(Object.keys(recorded), ['a/new.json', 'a/old.png']);
  assert.equal(recorded['a/old.png'].sha256, sha256(changed));
  assert.equal(recorded['a/old.png'].sourceCommit, git(root, 'rev-parse', 'HEAD').trim());
  assert.equal(recorded['a/old.png'].sourceTreeClean, true);
  assert.match(recorded['a/old.png'].environment.os, /\S/);
  await assert.rejects(readFile(lockPath(root)));
});

test('a later capture keeps the provenance of evidence it did not regenerate', async (t) => {
  const root = await repository(t);
  assert.equal(capture(root, stage({ 'a/old.png': changed })).status, 0);
  git(root, 'add', '.');
  git(root, 'commit', '-q', '-m', 'evidence');
  const first = (await manifest(root))['a/old.png'];
  assert.equal(capture(root, stage({ 'b/old.png': changed })).status, 0);
  const second = await manifest(root);
  assert.deepEqual(second['a/old.png'], first);
  assert.ok(second['b/old.png']);
});

test('a failing test command promotes nothing', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'a/new.png': PNG }, 1));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /did not succeed/);
  assert.equal(status(root), '');
});

test('one invalid artifact blocks the whole promotion', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ 'a/a.png': PNG, 'a/b.png': 'not an image', 'a/c.json': '{' }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /b\.png: not a PNG image/);
  assert.match(result.stderr, /c\.json: invalid JSON/);
  assert.equal(status(root), '');
});

test('a test cannot supply the provenance manifest itself', async (t) => {
  const root = await repository(t);
  const result = capture(root, stage({ [MANIFEST]: '{}', 'a/new.png': PNG }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /reserved/);
  assert.equal(status(root), '');
});

test('a write failure partway through leaves docs/assets unchanged', async (t) => {
  const root = await repository(t);
  // a/ is written first and succeeds; b/ cannot take new files.
  await chmod(join(root, 'docs', 'assets', 'b'), 0o555);
  const result = capture(root, stage({ 'a/old.png': changed, 'b/old.png': changed }));
  await chmod(join(root, 'docs', 'assets', 'b'), 0o755);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /docs\/assets was not changed/);
  assert.equal(status(root), '');
  assert.deepEqual(await leftovers(root), []);
});

test('a failure while swapping files in restores the previous evidence', { skip: process.platform !== 'darwin' && 'needs the macOS immutable flag' }, async (t) => {
  const root = await repository(t);
  // b/old.png cannot be moved aside, after a/old.png and a/added.png were already swapped in.
  assert.equal(spawnSync('chflags', ['uchg', join(root, 'docs', 'assets', 'b', 'old.png')]).status, 0);
  const result = capture(root, stage({ 'a/added.png': PNG, 'a/old.png': changed, 'b/old.png': changed }));
  spawnSync('chflags', ['nouchg', join(root, 'docs', 'assets', 'b', 'old.png')]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /previous evidence was restored/);
  assert.equal(status(root), '');
  assert.deepEqual(await leftovers(root), []);
});

test('uncommitted docs/assets changes stop the capture before anything runs', async (t) => {
  const root = await repository(t);
  const edited = Buffer.concat([PNG, Buffer.from('user edit')]);
  await writeFile(join(root, 'docs', 'assets', 'a', 'old.png'), edited);
  const result = capture(root, `require('node:fs').writeFileSync('ran', ''); ${stage({ 'a/old.png': PNG })}`);
  assert.equal(result.status, 2);
  assert.deepEqual(await readFile(join(root, 'docs', 'assets', 'a', 'old.png')), edited);
  await assert.rejects(readFile(join(root, 'frontend', 'ran')));
});

test('a held lock stops a second capture without touching it', async (t) => {
  const root = await repository(t);
  await writeFile(lockPath(root), 'other\n');
  const result = capture(root, `require('node:fs').writeFileSync('ran', ''); ${stage({ 'a/new.png': PNG })}`);
  assert.equal(result.status, 3);
  assert.match(result.stderr, /another evidence capture is running/);
  assert.equal(await readFile(lockPath(root), 'utf8'), 'other\n');
  await assert.rejects(readFile(join(root, 'frontend', 'ran')));
  assert.equal(status(root), '');
});

test('a capture started during another one cannot wipe its evidence', { timeout: 20_000 }, async (t) => {
  const root = await repository(t);
  const slow = `${stage({ 'a/new.png': PNG }).replace(/process\.exit\(0\);$/, '')}
    setTimeout(() => { fs.mkdirSync(path.join('test-results', 'evidence', 'b'), { recursive: true });
      fs.writeFileSync(path.join('test-results', 'evidence', 'b', 'new.png'), Buffer.from('${PNG.toString('hex')}', 'hex')); }, 1500);`;
  const first = captureAsync(t, root, slow);
  await new Promise((wait) => setTimeout(wait, 700));
  const second = capture(root, 'process.exit(1)');
  const { status: firstStatus, stderr } = await first.done;
  assert.equal(second.status, 3);
  assert.equal(firstStatus, 0, stderr);
  assert.equal(status(root), `?? docs/assets/a/new.png\n?? docs/assets/b/new.png\n?? docs/assets/${MANIFEST}\n`);
});

test('an interrupted capture promotes nothing and releases the lock', { timeout: 20_000 }, async (t) => {
  const root = await repository(t);
  const run = captureAsync(t, root, `${stage({ 'a/new.png': PNG }).replace(/process\.exit\(0\);$/, '')} setTimeout(() => {}, 1500);`);
  await new Promise((wait) => setTimeout(wait, 700));
  run.child.kill('SIGINT');
  const { status: exitStatus, stderr } = await run.done;
  assert.equal(exitStatus, 1);
  assert.match(stderr, /interrupted/);
  assert.equal(status(root), '');
  await assert.rejects(readFile(lockPath(root)));
});

test('evidence left from an earlier run is never promoted', async (t) => {
  const root = await repository(t);
  await mkdir(join(root, 'frontend', 'test-results', 'evidence', 'a'), { recursive: true });
  await writeFile(join(root, 'frontend', 'test-results', 'evidence', 'a', 'stale.png'), PNG);
  const result = capture(root, stage({ 'a/fresh.png': PNG }));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(status(root), `?? docs/assets/a/fresh.png\n?? docs/assets/${MANIFEST}\n`);
});

test('a run that writes docs/assets directly fails and keeps that change for review', async (t) => {
  const root = await repository(t);
  const result = capture(root, `require('node:fs').writeFileSync('../docs/assets/a/old.png', 'leak'); ${stage({ 'a/new.png': PNG })}`);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /wrote into docs\/assets directly/);
  assert.equal(status(root), ' M docs/assets/a/old.png\n');
  assert.equal(await readFile(join(root, 'docs', 'assets', 'a', 'old.png'), 'utf8'), 'leak');
});

test('symbolic links and empty runs are refused', async (t) => {
  const root = await repository(t);
  const linked = capture(root, `${stage({ 'a/a.png': PNG }).replace(/process\.exit\(0\);$/, '')}
    fs.symlinkSync('/etc/hosts', path.join('test-results', 'evidence', 'a', 'link.png')); process.exit(0);`);
  assert.equal(linked.status, 1);
  assert.match(linked.stderr, /link\.png: not a regular file/);
  const empty = capture(root, 'process.exit(0)');
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /produced no evidence/);
  assert.equal(status(root), '');
});
