// Regenerate committed browser evidence as one explicit, reviewable step.
//
//   node scripts/capture-browser-evidence.mjs -- <command...>
//
// Browser tests always write evidence to frontend/test-results/evidence (ignored).
// This script runs the given test command and, only if it succeeds and every
// artifact it produced is valid, publishes those artifacts into docs/assets
// together with a provenance manifest, for review with `git diff`.
//
// Guarantees, and their limits:
// - It never starts over uncommitted docs/assets changes, so nobody's work there
//   can be overwritten, and only one capture runs per working tree at a time.
// - Publication is all-or-nothing for every error the script can observe: all
//   files are first written next to their targets, then swapped in with the old
//   files kept as backups, and any failure restores the previous state.
// - A hard kill or power loss during the swap can still leave a mix. The
//   leftover *.evidence-* files are untracked, so the next capture refuses to
//   start, and Git holds the previous evidence.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { copyFile, lstat, mkdir, open, readFile, readdir, rename, rm, rmdir, unlink, writeFile } from 'node:fs/promises';
import { arch, platform, release } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryDirectory = resolve(frontendDirectory, '..');
const stagingDirectory = join(frontendDirectory, 'test-results', 'evidence');
const evidenceDirectory = join(repositoryDirectory, 'docs', 'assets');
const MANIFEST = 'browser-evidence-manifest.json';
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

class CaptureError extends Error {
  constructor(message, code = 1) {
    super(message);
    this.code = code;
  }
}

function git(...args) {
  const result = spawnSync('git', ['-C', repositoryDirectory, ...args], { encoding: 'utf8' });
  if (result.status !== 0) throw new CaptureError(`git ${args[0]} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

const evidenceChanges = () => git('status', '--porcelain=v1', '--untracked-files=all', '--', 'docs/assets');
const toPosix = (path) => path.split(sep).join('/');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(path));
    else files.push(path);
  }
  return files;
}

async function validate(path) {
  const info = await lstat(path);
  if (!info.isFile()) return 'not a regular file';
  if (info.size === 0) return 'empty';
  const bytes = await readFile(path);
  if (path.endsWith('.png')) return bytes.subarray(0, 8).equals(PNG_SIGNATURE) ? null : 'not a PNG image';
  if (path.endsWith('.json')) {
    try { JSON.parse(bytes.toString('utf8')); return null; } catch { return 'invalid JSON'; }
  }
  return 'unexpected file type (only .png and .json are promoted)';
}

async function versionOf(relativePath, pick) {
  try { return pick(JSON.parse(await readFile(join(frontendDirectory, 'node_modules', relativePath), 'utf8'))) ?? 'unknown'; }
  catch { return 'unknown'; }
}

async function readManifest() {
  let text;
  try { text = await readFile(join(evidenceDirectory, MANIFEST), 'utf8'); } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
  const manifest = JSON.parse(text);
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) throw new CaptureError(`${MANIFEST} is not a JSON object`);
  return manifest;
}

// Writes every file next to its target, then swaps them in. On any error the
// previous files are put back and every temporary file is removed.
async function publish(entries) {
  const tag = `.evidence-${process.pid}-${randomBytes(4).toString('hex')}`;
  const plan = entries.map((entry) => ({ ...entry, temporary: `${entry.target}${tag}.tmp`, backup: `${entry.target}${tag}.bak` }));
  const createdDirectories = [];
  const cleanUp = async () => {
    for (const step of plan) await rm(step.temporary, { force: true }).catch(() => {});
    for (const directory of createdDirectories.reverse()) await rmdir(directory).catch(() => {});
  };

  try {
    for (const step of plan) {
      const created = await mkdir(dirname(step.target), { recursive: true });
      if (created) createdDirectories.push(created);
      if (step.source) await copyFile(step.source, step.temporary);
      else await writeFile(step.temporary, step.content);
      if (sha256(await readFile(step.temporary)) !== step.sha256) throw new Error(`${step.path}: written file does not match`);
    }
  } catch (error) {
    await cleanUp();
    throw new CaptureError(`could not write the new evidence (${error.message}); docs/assets was not changed.`);
  }

  const swapped = [];
  try {
    for (const step of plan) {
      step.hadPrevious = await lstat(step.target).then(() => true, () => false);
      if (step.hadPrevious) await rename(step.target, step.backup);
      swapped.push(step);
      await rename(step.temporary, step.target);
      step.installed = true;
    }
  } catch (error) {
    const unrestored = [];
    for (const step of swapped.reverse()) {
      try {
        if (step.installed) await unlink(step.target);
        if (step.hadPrevious) await rename(step.backup, step.target);
      } catch { unrestored.push(step.path); }
    }
    await cleanUp();
    if (unrestored.length > 0) {
      throw new CaptureError(`publishing failed (${error.message}) and these files could not be restored; recover them with \`git checkout -- <path>\`:\n  ${unrestored.join('\n  ')}`);
    }
    throw new CaptureError(`publishing failed (${error.message}); the previous evidence was restored.`);
  }

  for (const step of plan) if (step.hadPrevious) await unlink(step.backup).catch(() => {});
}

async function main() {
  const separator = process.argv.indexOf('--');
  const command = separator === -1 ? [] : process.argv.slice(separator + 1);
  if (command.length === 0) throw new CaptureError('usage: capture-browser-evidence.mjs -- <test command...>', 2);

  if (evidenceChanges() !== '') {
    throw new CaptureError('docs/assets has uncommitted changes. Commit or stash them first; nothing was run or changed.', 2);
  }

  // The lock lives in this working tree's Git directory, which test runs never clean.
  const lockPath = resolve(repositoryDirectory, git('rev-parse', '--git-path', 'evidence-capture.lock').trim());
  let lock;
  try { lock = await open(lockPath, 'wx'); } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    throw new CaptureError(`another evidence capture is running in this working tree. If none is, delete ${lockPath}.`, 3);
  }
  let interrupted = false;
  const stop = () => { interrupted = true; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  try {
    await lock.writeFile(`${process.pid}\n`);
    await rm(stagingDirectory, { recursive: true, force: true });
    const sourceCommit = git('rev-parse', 'HEAD').trim();
    const sourceTreeClean = git('status', '--porcelain', '--untracked-files=no').trim() === '';
    const run = spawnSync(command[0], command.slice(1), {
      cwd: frontendDirectory,
      stdio: 'inherit',
      // CI=1 stops Playwright from reusing an unrelated server that already holds the preview port.
      env: { ...process.env, CI: '1' },
    });

    const leaked = evidenceChanges();
    if (leaked !== '') throw new CaptureError(`the test run wrote into docs/assets directly; nothing was promoted. Review these changes:\n${leaked}`);
    if (interrupted) throw new CaptureError('the capture was interrupted; nothing was promoted.');
    if (run.error || run.status !== 0) {
      throw new CaptureError(`the test command did not succeed (${run.error?.message ?? `exit ${run.status ?? run.signal}`}); nothing was promoted.`);
    }

    const files = (await listFiles(stagingDirectory)).sort();
    if (files.length === 0) throw new CaptureError('the test run produced no evidence; nothing was promoted.');
    const problems = [];
    for (const file of files) {
      const problem = await validate(file);
      if (problem) problems.push(`${relative(stagingDirectory, file)}: ${problem}`);
    }
    if (problems.length > 0) throw new CaptureError(`invalid evidence; nothing was promoted:\n  ${problems.join('\n  ')}`);

    const environment = {
      os: `${platform()} ${release()} ${arch()}`,
      node: process.version,
      playwright: await versionOf('@playwright/test/package.json', (pkg) => pkg.version),
      chromium: await versionOf('playwright-core/browsers.json', (data) => data.browsers?.find((browser) => browser.name === 'chromium')?.browserVersion),
    };
    const capturedAt = new Date().toISOString();
    const manifest = await readManifest();
    const entries = [];
    for (const file of files) {
      const path = toPosix(relative(stagingDirectory, file));
      if (path === MANIFEST) throw new CaptureError(`a test produced ${MANIFEST}, which is reserved; nothing was promoted.`);
      const digest = sha256(await readFile(file));
      entries.push({ path, source: file, target: join(evidenceDirectory, path), sha256: digest });
      manifest[path] = { sha256: digest, capturedAt, sourceCommit, sourceTreeClean, environment, command: command.join(' ') };
    }
    const sorted = Object.fromEntries(Object.keys(manifest).sort().map((key) => [key, manifest[key]]));
    const manifestText = `${JSON.stringify(sorted, null, 2)}\n`;
    entries.push({ path: MANIFEST, content: manifestText, target: join(evidenceDirectory, MANIFEST), sha256: sha256(Buffer.from(manifestText)) });

    if (interrupted) throw new CaptureError('the capture was interrupted; nothing was promoted.');
    await publish(entries);

    const promoted = entries.slice(0, -1).map((entry) => `docs/assets/${entry.path}`);
    const capturedDirectories = new Set(promoted.map((path) => path.split('/').slice(0, 3).join('/')));
    const notRegenerated = git('ls-files', '--', ...capturedDirectories).split('\n')
      .filter((path) => path && !promoted.includes(path) && path !== `docs/assets/${MANIFEST}`);

    console.log(`\nPromoted ${promoted.length} evidence files into docs/assets and recorded them in docs/assets/${MANIFEST}.`);
    if (notRegenerated.length > 0) {
      console.log(`${notRegenerated.length} committed files in the same directories were not regenerated by this run and may be stale:`);
      for (const path of notRegenerated) console.log(`  ${path}`);
    }
    console.log(`  source commit: ${sourceCommit}${sourceTreeClean ? '' : ' (with uncommitted changes)'}`);
    console.log(`  environment:   ${environment.os}, Node ${environment.node}, Playwright ${environment.playwright}, Chromium ${environment.chromium}`);
    console.log('\nReview with `git diff --stat -- docs/assets` before committing.');
  } finally {
    await lock.close().catch(() => {});
    await unlink(lockPath).catch(() => {});
  }
}

try {
  await main();
} catch (error) {
  if (!(error instanceof CaptureError)) throw error;
  console.error(`evidence capture: ${error.message}`);
  process.exitCode = error.code;
}
