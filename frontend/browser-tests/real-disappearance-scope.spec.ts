import { expect, test, type Page } from '@playwright/test';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// Normal (non-investigation) comparison with real FastAPI and Semgrep: one file becomes ignored and
// another is renamed between the scans. The comparison must stay available, and its notes must state
// only what each scan's coverage report supports.
test('real comparison states the current scan exclusions next to findings that disappeared', async ({ page }) => {
  test.setTimeout(90_000);
  const token = process.env.BROWSER_E2E_API_TOKEN;
  const targetPath = process.env.BROWSER_E2E_SCOPE_PATH;
  if (!token || !targetPath) throw new Error('real_scope_e2e_configuration_required');
  const scans: Array<{ limitations: string[]; scan_status: string; findings: Array<{ file_path: string }> }> = [];
  page.on('response', async (response) => {
    if (new URL(response.url()).pathname === '/api/v1/scans') scans.push(await response.json());
  });

  const runScan = async () => {
    const done = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/v1/scans');
    await page.getByRole('button', { name: '검사 실행' }).click();
    await done;
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
});

async function download(page: Page): Promise<string> {
  const event = page.waitForEvent('download');
  await page.getByRole('button', { name: '비교 보고서 내보내기' }).click();
  const file = await (await event).path();
  if (!file) throw new Error('comparison_download_missing');
  return readFile(file, 'utf8');
}
