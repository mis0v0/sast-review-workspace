import { expect, test, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The documented one-project launch, `python -m ai_code_security_analyzer.api PROJECT_DIR`,
// driven through the real dashboard with real Semgrep. The spec starts and stops its own servers.

const repositoryDirectory = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const token = 'K'.repeat(43);
// Synthetic source written to fixture files for Semgrep to flag; it is never executed.
const vulnerable = 'function run(input) {\n  return eval(input);\n}\nmodule.exports = run;\n';

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => (address && typeof address !== 'string' ? resolvePort(address.port) : reject(new Error('no_port'))));
    });
  });
}

function portOpen(port: number): Promise<boolean> {
  return new Promise((done) => {
    const socket = net.connect(port, '127.0.0.1');
    socket.once('connect', () => { socket.destroy(); done(true); });
    socket.once('error', () => done(false));
  });
}

class Launcher {
  private child: ChildProcess | null = null;
  output = '';
  constructor(readonly port: number) {}

  /** Starts the launcher and returns the dashboard address it prints. */
  async start(project: string): Promise<string> {
    if (this.child) throw new Error('launcher_already_started');
    if (await portOpen(this.port)) throw new Error('launcher_port_already_in_use');
    this.output = '';
    const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('AI_CODE_SECURITY_')));
    this.child = spawn('uv', ['run', '--locked', 'python', '-m', 'ai_code_security_analyzer.api', project, '--port', String(this.port)], {
      cwd: repositoryDirectory,
      env: { ...environment, AI_CODE_SECURITY_API_TOKEN: token, SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child.stdout!.on('data', (chunk: Buffer) => { this.output += chunk.toString(); });
    this.child.stderr!.on('data', (chunk: Buffer) => { this.output += chunk.toString(); });
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      if (this.child.exitCode !== null) throw new Error(`launcher_exited: ${this.output}`);
      const shown = /Dashboard {2}(http:\/\/127\.0\.0\.1:\d+\/)/.exec(this.output);
      if (shown && await portOpen(this.port)) return shown[1];
      await new Promise((done) => setTimeout(done, 200));
    }
    throw new Error('launcher_start_timeout');
  }

  async stop(): Promise<void> {
    const child = this.child;
    this.child = null;
    if (!child || child.exitCode !== null) return;
    const closed = new Promise((done) => child.once('close', done));
    try { process.kill(-child.pid!, 'SIGINT'); } catch { child.kill('SIGINT'); }
    const graceful = await Promise.race([closed.then(() => true), new Promise((done) => setTimeout(() => done(false), 10_000))]);
    if (!graceful) {
      try { process.kill(-child.pid!, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      await closed;
    }
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (!(await portOpen(this.port))) return;
      await new Promise((done) => setTimeout(done, 100));
    }
    throw new Error('launcher_still_listening');
  }
}

async function scan(page: Page, confirm = false) {
  const responded = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  const startView = page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ });
  if (await startView.isVisible()) await startView.click();
  const dialog = confirm ? page.waitForEvent('dialog').then((prompt) => prompt.accept()) : null;
  await page.getByRole('button', { name: '검사 실행' }).click();
  await dialog;
  return responded;
}

test.describe('one-project launcher', () => {
  test.describe.configure({ mode: 'serial' });
  let root = '';
  let launcher: Launcher;

  test.beforeAll(async () => {
    root = await mkdtemp(join(await realpath(tmpdir()), 'aicsa-launcher-e2e-'));
    launcher = new Launcher(await freePort());
  });
  test.afterEach(async () => { await launcher?.stop(); });
  test.afterAll(async () => {
    await launcher?.stop();
    if (root) await rm(root, { recursive: true, force: true });
  });

  test('a Node.js project at a path with spaces and Unicode, then a Python project after a restart', async ({ page }) => {
    test.setTimeout(240_000);
    const node = join(root, 'web app — 테스트');
    await mkdir(join(node, 'src'), { recursive: true });
    await writeFile(join(node, 'package.json'), '{"name": "web-app", "version": "1.0.0"}\n');
    await writeFile(join(node, 'src', 'index.js'), vulnerable);
    const python = join(root, 'py service ünï');
    await mkdir(join(python, 'service'), { recursive: true });
    await writeFile(join(python, 'pyproject.toml'), '[project]\nname = "service"\nversion = "0.1.0"\n');
    await writeFile(join(python, 'service', 'app.py'), 'def handler(request):\n    return request.args.get("name")\n');

    const dashboard = await launcher.start(node);
    expect(dashboard).toBe(`http://127.0.0.1:${launcher.port}/`);
    expect(launcher.output).toContain('web app — 테스트');
    expect(launcher.output).toContain('(not shown)');
    expect(launcher.output).not.toContain(token);

    await page.goto(dashboard);
    await expect(page.getByText('API 연결됨')).toBeVisible();
    await page.getByLabel('로컬 API 토큰').fill(token);
    const first = await scan(page);
    expect(first.status()).toBe(200);
    const firstInstance = first.headers()['x-server-instance'];
    await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
    const findings = page.getByRole('region', { name: 'Finding 목록' });
    await findings.getByRole('button', { name: /src\/index\.js/ }).click();
    await page.getByLabel('수동 검토 상태').selectOption('reviewed');
    await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
    // The page never learns the project path.
    expect(await page.content()).not.toContain(root);

    // Restart on another project, same port and token, same tab.
    await launcher.stop();
    await launcher.start(python);
    const crossed = await scan(page, true);
    expect(crossed.headers()['x-server-instance']).not.toBe(firstInstance);
    await expect(page.getByText(/검사 서버가 다시 시작된 것을 확인했습니다/).first()).toBeVisible();
    await expect(page.getByText('API 연결됨')).toBeVisible();

    // The Python project: no bundled rule applies, so the scan is partial, not a clean result.
    // With unsaved review work on screen, the partial result is not applied (existing behaviour).
    await scan(page, true);
    await expect(page.getByRole('alert')).toContainText('새 검사가 부분 검사로 끝나 결과를 적용하지 않았습니다');
    await findings.getByRole('button', { name: /src\/index\.js/ }).click();
    await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');

    // A fresh tab shows it. The token is kept only in page memory, so it is entered again.
    await page.reload();
    await expect(page.getByText('API 연결됨')).toBeVisible();
    await expect(page.getByLabel('로컬 API 토큰')).toHaveValue('');
    await page.getByLabel('로컬 API 토큰').fill(token);
    await scan(page);
    await expect(page.getByRole('heading', { name: '부분 검사', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: /일부 파일이나 규칙의 결과가 빠졌을 수 있습니다/ })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Finding 목록' })).toHaveCount(0);
  });
});
