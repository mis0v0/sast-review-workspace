import { expect, test, type Page, type Response } from '@playwright/test';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// Normal (non-investigation) comparison with real FastAPI and Semgrep: one file becomes ignored and
// another is renamed between the scans. The comparison must stay available, and its notes must state
// only what each scan's coverage report supports.
test('real comparison states the current scan exclusions next to findings that disappeared', async ({ page }) => {
  test.setTimeout(90_000);
  const token = process.env.BROWSER_E2E_API_TOKEN;
  const targetPath = process.env.BROWSER_E2E_SCOPE_PATH;
  const rulesPath = process.env.BROWSER_E2E_RULES_PATH;
  if (!token || !targetPath || !rulesPath) throw new Error('real_scope_e2e_configuration_required');
  const scans: Scan[] = [];

  // Each scan is tied to the one POST response its click triggers, and its body is parsed before
  // runScan returns, so the assertions below never read a scan that has not been stored yet.
  const runScan = async () => {
    const done = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/v1/scans');
    await page.getByRole('button', { name: '검사 실행' }).click();
    scans.push(await scanBody(await done));
    await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  };

  await page.goto('/');
  await expect(page.getByText(/API 연결됨/)).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByLabel('검사 대상').selectOption('synthetic-scope');
  await page.getByLabel('검사 규칙 모음').selectOption('baseline');
  await runScan();
  expect(scans[0].findings.map((finding) => finding.file_path).sort()).toEqual(['hidden.js', 'kept.js']);
  expect(scans[0].limitations).not.toContain('paths_excluded_by_ignore_rules');
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();

  await writeFile(join(targetPath, '.semgrepignore'), 'hidden.js\n', { mode: 0o600 });
  await rename(join(targetPath, 'kept.js'), join(targetPath, 'moved.js'));
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await runScan();
  // Real Semgrep evidence for the claim below: completed, with an ignore-rule exclusion.
  expect(scans[1].scan_status).toBe('completed');
  expect(scans[1].limitations).toContain('paths_excluded_by_ignore_rules');
  expect(scans[1].findings.map((finding) => finding.file_path)).toEqual(['moved.js']);

  await page.getByText('검사 결과 비교').click();
  // Same server, same rule file bytes for both scans: the real header lets the comparison say so.
  const comparison = page.getByRole('region', { name: '검사 결과 비교' });
  await expect(comparison.getByRole('note').filter({ hasText: '선택 규칙 파일의 바이트가 모두 같습니다' })).toHaveCount(1);
  await expect(page.getByText(/이번만 1 · 양쪽 0 · 기준만 2$/)).toBeVisible();
  const categories = page.getByRole('group', { name: '비교 항목 범주' });
  await categories.getByRole('button', { name: /기준 검사에서만 관찰/ }).click();
  const baselineOnly = page.getByRole('region', { name: '기준 검사에서만 관찰 목록' });
  await expect(baselineOnly).toContainText('hidden.js');
  await expect(baselineOnly).toContainText('kept.js');
  const note = baselineOnly.getByRole('note');
  await expect(note).toContainText('현재 검사는 무시 규칙(.semgrepignore 또는 Semgrep 기본 제외)으로 일부 경로를 제외했습니다');
  await expect(note).toContainText('어떤 파일이 제외됐는지 알 수 없습니다');
  await expect(note).not.toContainText('hidden.js');

  await categories.getByRole('button', { name: /이번 검사에서만 관찰/ }).click();
  const currentOnly = page.getByRole('region', { name: '이번 검사에서만 관찰 목록' });
  await expect(currentOnly).toContainText('moved.js');
  await expect(currentOnly.getByRole('note')).toContainText('기준 검사는 기본 제외(.git, node_modules, .venv) 외에 제외한 경로가 없다고 보고했습니다');

  const markdown = await download(page);
  const section = markdown.slice(markdown.indexOf('## 검사 범위와 미관찰 원인'), markdown.indexOf('## 이번 검사에서만 관찰'));
  expect(section).toContain('어떤 파일이 제외됐는지 알 수 없습니다');
  expect(section).not.toContain(targetPath);
  expect(markdown).not.toContain(token);
  expect(markdown).toContain('- 규칙 파일 내용: 같음');

  // A8-R3 reproduction: keep the code, change the rule behind the same rule ID and profile.
  const rulePath = join(rulesPath, 'security-baseline.yml');
  const originalRule = await readFile(rulePath, 'utf8');
  const anchor = '  - id: baseline.javascript-dynamic-eval\n';
  expect(originalRule.split(anchor)).toHaveLength(2);
  try {
    await writeFile(rulePath, originalRule.replace(anchor, `${anchor}    paths:\n      exclude:\n        - moved.js\n`));
    await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
    await runScan();
    expect(scans[2].findings).toEqual([]);
    // Semgrep reports no skipped path for a rule-level filter: the coverage report is exactly as before,
    // so scope evidence alone cannot explain the disappearance.
    expect(scans[2].limitations).toEqual(scans[1].limitations);
    await expect(page.getByText(/이번만 0 · 양쪽 0 · 기준만 2 · 규칙 내용 다름/)).toBeVisible();
    const details = comparison.locator('details.comparison-content');
    if (!await details.evaluate((element) => (element as HTMLDetailsElement).open)) await page.getByText('검사 결과 비교').click();
    await expect(comparison.getByRole('note').filter({ hasText: '선택 규칙 파일의 바이트가 다릅니다' })).toHaveCount(1);
    const driftMarkdown = await download(page);
    expect(driftMarkdown).toContain('- 규칙 파일 내용: 다름');
    // The report's own disclaimer negates these phrases; only the statements this comparison derives are checked.
    const driftScope = driftMarkdown.slice(driftMarkdown.indexOf('## 검사 범위와 미관찰 원인'), driftMarkdown.indexOf('## 이번 검사에서만 관찰'));
    expect(driftScope).toContain('규칙 변경 때문일 수 있으며');
    expect(driftScope).not.toMatch(/해결됐|수정됐|수정 완료|해결 완료/);
  } finally {
    await writeFile(rulePath, originalRule);
  }
});

type Scan = { limitations: string[]; scan_status: string; findings: Array<{ file_path: string }> };

// A failed or malformed scan response stops the test instead of becoming an entry in `scans`.
async function scanBody(response: Response): Promise<Scan> {
  if (response.status() !== 200) throw new Error(`scan_response_status_${response.status()}`);
  const scan = await response.json() as Partial<Scan> | null;
  if (typeof scan !== 'object' || scan === null || typeof scan.scan_status !== 'string' || !Array.isArray(scan.limitations) || !Array.isArray(scan.findings)) {
    throw new Error('scan_response_malformed');
  }
  return scan as Scan;
}

async function download(page: Page): Promise<string> {
  const event = page.waitForEvent('download');
  await page.getByRole('button', { name: '비교 보고서 내보내기' }).click();
  const file = await (await event).path();
  if (!file) throw new Error('comparison_download_missing');
  return readFile(file, 'utf8');
}
