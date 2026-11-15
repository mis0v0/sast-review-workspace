import { expect, test, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Real FastAPI and Semgrep processes, restarted on the same port with the same token.
// This spec starts and stops its own servers; it does not use the shared E2E server.

const repositoryDirectory = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const token = 'R'.repeat(43);
// Synthetic source written to fixture files for Semgrep to flag; it is never executed.
const vulnerable = 'function run(input) {\n  return eval(input);\n}\n';
const instanceHeader = 'x-server-instance';

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

class ApiServer {
  private child: ChildProcess | null = null;
  constructor(readonly port: number, readonly allowedOrigins: string[]) {}
  get origin() { return `http://127.0.0.1:${this.port}`; }

  async start(target: string): Promise<void> {
    if (this.child) throw new Error('api_server_already_started');
    // Never mistake a leftover process on this port for the one started here.
    if (await portOpen(this.port)) throw new Error('api_port_already_in_use');
    const entry = "import sys, uvicorn; from ai_code_security_analyzer.api.app import create_app_from_env; "
      + "uvicorn.run(create_app_from_env(investigation_api_enabled=True), host='127.0.0.1', port=int(sys.argv[1]), access_log=False, workers=1)";
    this.child = spawn('uv', ['run', '--locked', 'python', '-c', entry, String(this.port)], {
      cwd: repositoryDirectory,
      env: {
        ...process.env,
        AI_CODE_SECURITY_TARGET: target,
        AI_CODE_SECURITY_API_TOKEN: token,
        AI_CODE_SECURITY_ALLOWED_ORIGINS: this.allowedOrigins.join(','),
        SEMGREP_SEND_METRICS: 'off',
        SEMGREP_ENABLE_VERSION_CHECK: '0',
      },
      detached: true,
      stdio: 'ignore',
    });
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      if (this.child.exitCode !== null) throw new Error('api_server_failed_to_start');
      if (await portOpen(this.port) && (await fetch(`${this.origin}/api/v1/health`)).ok) return;
      await new Promise((done) => setTimeout(done, 200));
    }
    throw new Error('api_server_start_timeout');
  }

  async stop(): Promise<void> {
    const child = this.child;
    this.child = null;
    if (!child || child.exitCode !== null) return;
    const closed = new Promise((done) => child.once('close', done));
    try { process.kill(-child.pid!, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
    await closed;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (!(await portOpen(this.port))) return;
      await new Promise((done) => setTimeout(done, 100));
    }
    throw new Error('api_server_still_listening');
  }
}

/** Two different projects whose findings sit at identical rules and positions, so their scan bodies are byte-identical. */
async function projects(root: string): Promise<{ first: string; second: string }> {
  const first = join(root, 'payments-service');
  const second = join(root, 'unrelated-reporting-tool');
  for (const project of [first, second]) {
    await mkdir(join(project, 'src'), { recursive: true });
    await writeFile(join(project, 'src', 'alpha.js'), vulnerable);
    await writeFile(join(project, 'src', 'beta.js'), vulnerable);
  }
  await writeFile(join(second, 'README.md'), 'A different project.\n');
  await writeFile(join(second, 'src', 'report.js'), 'export const title = "monthly report";\n');
  return { first, second };
}

async function connect(page: Page, origin: string): Promise<void> {
  await page.goto(`${origin}/`);
  await expect(page.getByText('API 연결됨')).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill(token);
}

async function startScan(page: Page, confirm: boolean): Promise<void> {
  const startView = page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ });
  if (await startView.isVisible()) await startView.click();
  const dialog = confirm ? page.waitForEvent('dialog').then((prompt) => prompt.accept()) : null;
  await page.getByRole('button', { name: '검사 실행' }).click();
  await dialog;
}

async function scanAndWait(page: Page, confirm = false) {
  const responded = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  await startScan(page, confirm);
  return responded;
}

async function markFirstFindingReviewed(page: Page): Promise<void> {
  await page.getByRole('region', { name: 'Finding 목록' }).getByRole('button', { name: /src\/alpha\.js/ }).click();
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
}

test.describe('server restart with the same port and token', () => {
  test.describe.configure({ mode: 'serial' });
  let root = '';
  let api: ApiServer;
  let pageOrigin = '';

  test.beforeAll(async () => {
    root = await mkdtemp(join(await realpath(tmpdir()), 'aicsa-restart-e2e-'));
    const port = await freePort();
    pageOrigin = `http://127.0.0.1:${await freePort()}`;
    api = new ApiServer(port, [`http://127.0.0.1:${port}`, pageOrigin]);
  });
  test.afterEach(async () => { await api?.stop(); });
  test.afterAll(async () => {
    await api?.stop();
    if (root) await rm(root, { recursive: true, force: true });
  });

  test('a stale tab cannot carry a baseline, a result or review work across a restart', async ({ page }) => {
    test.setTimeout(240_000);
    const { first, second } = await projects(root);
    await api.start(first);
    await connect(page, api.origin);

    // Same project, same server: an ordinary rescan comparison still works.
    const firstResponse = await scanAndWait(page);
    const firstInstance = firstResponse.headers()[instanceHeader];
    expect(firstInstance).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const firstBody = await firstResponse.text();
    await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
    await page.getByRole('button', { name: /비교 기준/ }).click();
    const sameServer = await scanAndWait(page);
    expect(sameServer.headers()[instanceHeader]).toBe(firstInstance);
    await expect(page.getByLabel('Finding 관찰 차이')).toContainText('양쪽에서 관찰');
    await expect(page.getByRole('button', { name: '비교 보고서 내보내기' })).toBeEnabled();
    await markFirstFindingReviewed(page);

    // Restart on a different project, same port and token, without reloading the tab.
    await api.stop();
    await api.start(second);

    // The first request reaches the new process. Its answer is not applied to the old page state.
    const crossed = await scanAndWait(page, true);
    const secondInstance = crossed.headers()[instanceHeader];
    expect(crossed.status()).toBe(200);
    expect(secondInstance).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(secondInstance).not.toBe(firstInstance);
    // The reproduced defect: the body alone cannot tell the two projects apart.
    expect(await crossed.text()).toBe(firstBody);
    await expect(page.getByText(/검사 서버가 다시 시작된 것을 확인했습니다/).first()).toBeVisible();
    // The previous result and the unsaved review record are kept, not replaced.
    await page.getByRole('region', { name: 'Finding 목록' }).getByRole('button', { name: /src\/alpha\.js/ }).click();
    await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
    await expect(page.locator('.retained-result-note')).toBeVisible();

    // Options were reloaded from the new process; the next scan is accepted, but never compared with the old baseline.
    await expect(page.getByText('API 연결됨')).toBeVisible();
    const accepted = await scanAndWait(page, true);
    expect(accepted.headers()[instanceHeader]).toBe(secondInstance);
    await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
    const blocked = page.locator('.comparison-blocked');
    await expect(blocked).toContainText('서로 다른 서버 실행에서 만들어져 비교하지 않았습니다');
    await expect(page.getByLabel('Finding 관찰 차이')).toHaveCount(0);
    await expect(page.getByRole('button', { name: '비교 보고서 내보내기' })).toBeDisabled();

    // Within the new process a fresh baseline compares normally again.
    await page.getByRole('button', { name: '비교 기준 해제' }).click();
    await page.getByRole('button', { name: /비교 기준/ }).first().click();
    await scanAndWait(page);
    await expect(page.getByLabel('Finding 관찰 차이')).toContainText('양쪽에서 관찰');
    await expect(page.locator('.comparison-blocked')).toHaveCount(0);
  });

  test('a scan in flight when the server goes away leaves no result and no evidence', async ({ page }) => {
    test.setTimeout(240_000);
    const { first, second } = await projects(join(root, 'in-flight'));
    await api.start(first);
    await connect(page, api.origin);
    await page.getByText('소멸 근거 조사 선택').click();
    await page.getByLabel('소멸 근거 조사').check();
    const before = await page.evaluate(() => performance.now());

    const evidenceRequest = page.waitForRequest((request) => request.url().endsWith('/api/v2/investigation-scans'));
    await startScan(page, false);
    await evidenceRequest;
    await api.stop();
    await api.start(second);
    await expect(page.getByText('로컬 API에 연결할 수 없습니다.').first()).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole('heading', { name: '정상 완료' })).toHaveCount(0);
    await expect(page.getByRole('region', { name: 'Finding 목록' })).toHaveCount(0);
    expect(await page.evaluate((start) => performance.now() > start, before)).toBe(true);

    // The next scan reaches the new process and is refused because the page still holds the old options.
    const crossed = page.waitForResponse((response) => response.url().endsWith('/api/v2/investigation-scans'));
    await startScan(page, false);
    expect((await crossed).status()).toBe(200);
    await expect(page.getByText(/검사 서버가 다시 시작된 것을 확인했습니다/).first()).toBeVisible();
    await expect(page.getByRole('region', { name: 'Finding 목록' })).toHaveCount(0);
  });

  test('a page on another allowed origin can read the instance header; other origins cannot', async ({ page }) => {
    test.setTimeout(120_000);
    const { first } = await projects(join(root, 'cross-origin'));
    await api.start(first);
    // Real loopback pages, as a development server would serve them. (A Playwright-intercepted page is
    // not on loopback, so Chromium's local network access rule would refuse every request it makes.)
    const pages: http.Server[] = [];
    const servePage = async (port: number) => {
      const server = http.createServer((_request, response) => {
        response.writeHead(200, { 'Content-Type': 'text/html' });
        response.end('<!doctype html><title>probe</title>');
      });
      await new Promise<void>((done) => server.listen(port, '127.0.0.1', done));
      pages.push(server);
      return `http://127.0.0.1:${port}/`;
    };
    try {
      const allowed = await servePage(Number(new URL(pageOrigin).port));
      await page.goto(allowed);
      const read = await page.evaluate(async (url) => {
        const options = await fetch(`${url}/api/v1/options`, { cache: 'no-store', credentials: 'omit' });
        const scan = await fetch(`${url}/api/v1/scans`, { method: 'POST', cache: 'no-store', credentials: 'omit',
          headers: { 'Content-Type': 'application/json', 'X-Local-API-Token': 'R'.repeat(43) },
          body: JSON.stringify({ target_id: 'unknown-target', rule_profile_id: 'baseline' }) });
        const denied = await fetch(`${url}/api/v1/scans`, { method: 'POST', cache: 'no-store', credentials: 'omit',
          headers: { 'Content-Type': 'application/json', 'X-Local-API-Token': 'w'.repeat(43) },
          body: JSON.stringify({ target_id: 'local-project', rule_profile_id: 'baseline' }) }).then((response) => response.status, () => 'unreadable');
        return {
          status: options.status, instance: options.headers.get('X-Server-Instance'),
          errorStatus: scan.status, errorInstance: scan.headers.get('X-Server-Instance'), denied,
        };
      }, api.origin);
      expect(read.status).toBe(200);
      expect(read.instance).toMatch(/^[A-Za-z0-9_-]{22}$/);
      // A handler error is readable and names the same process.
      expect(read.errorStatus).toBe(404);
      expect(read.errorInstance).toBe(read.instance);
      // Boundary denials carry no CORS grant, so a cross-origin page cannot read them (unchanged behaviour).
      expect(read.denied).toBe('unreadable');

      await page.goto(await servePage(await freePort()));
      const refused = await page.evaluate(async (url) => fetch(`${url}/api/v1/options`)
        .then((response) => response.headers.get('X-Server-Instance'), () => 'unreadable'), api.origin);
      expect(refused).toBe('unreadable');
    } finally {
      await Promise.all(pages.map((server) => new Promise((done) => server.close(done))));
    }
  });
});
