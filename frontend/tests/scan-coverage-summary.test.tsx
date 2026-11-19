import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { App } from '../src/app/App';
import { BUILT_IN_PROFILE_SCOPES, describeScanCoverage } from '../src/features/scans/scanCoverage';

const repo = resolve(process.cwd(), '..');
const finding: ApiFinding = { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.javascript-dynamic-eval', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/app.js', line_number: 3, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null };
const BASE = ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'];
const completed = (findings: ApiFinding[], extra: string[] = []): ScanResponse => ({ scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: [...BASE, ...extra] });
const partial = (findings: ApiFinding[]): ScanResponse => ({ ...completed(findings), scan_status: 'partial', completed: false, issues: ['evidence_unavailable'], limitations: [...BASE, 'scan_partial'] });
const failed = (): ScanResponse => ({ ...completed([]), scan_status: 'execution_failed', completed: false, semgrep_version: null, issues: ['semgrep_failed'], limitations: [...BASE, 'scan_failed'] });

// Claims a coverage statement must never make (Korean renderings of "all checks passed",
// "no vulnerabilities", "secure", "safe to deploy", "all files inspected", "fixed").
const UNSUPPORTED = ['모든 보안 검사', '검사를 통과', '취약점이 없습니다', '취약점 없음', '안전합니다', '안전한 앱', '배포해도', '모든 파일을 검사', '모든 파일이 검사', '수정됐습니다', '수정되었습니다', '해결됐습니다'];
const allText = (statement: ReturnType<typeof describeScanCoverage>) => JSON.stringify(statement);

describe('built-in scope matches the production rule configuration', () => {
  const serverProfiles = [...readFileSync(resolve(repo, 'src/ai_code_security_analyzer/services/scan_service.py'), 'utf8')
    .matchAll(/RuleProfile\(\s*"([^"]+)",\s*"[^"]*",\s*"([^"]+)"/g)].map((m) => [m[1], m[2]] as const);

  it('describes exactly the server rule profiles, with the same rule files', () => {
    expect(serverProfiles.length).toBeGreaterThan(0);
    expect(Object.keys(BUILT_IN_PROFILE_SCOPES).sort()).toEqual(serverProfiles.map(([id]) => id).sort());
    for (const [id, file] of serverProfiles) expect(BUILT_IN_PROFILE_SCOPES[id].ruleFile, id).toBe(file);
  });

  it.each(Object.entries(BUILT_IN_PROFILE_SCOPES))('lists exactly the rule ids in %s rule file', (_id, scope) => {
    const ids = [...readFileSync(resolve(repo, 'rules', scope.ruleFile), 'utf8').matchAll(/^ {2}- id: (\S+)$/gm)].map((m) => m[1]);
    expect([...scope.ruleIds].sort()).toEqual(ids.sort());
  });
});

describe('coverage statement classification', () => {
  it('keeps configured checks out of what the scan observed', () => {
    const statement = describeScanCoverage(completed([finding]), 'baseline');
    expect(statement.configured?.checks).toHaveLength(3);
    for (const check of statement.configured!.checks) expect(statement.observed.join(' ')).not.toContain(check);
    expect(statement.observed.join(' ')).not.toMatch(/규칙이 실행|모든 파일/);
    expect(statement.unavailable.join(' ')).toContain('각 규칙이 실제로 어떤 파일에 적용됐는지는 이 화면에 제공되지 않습니다');
  });

  it('reports exclusions only from exclusion evidence, and an unknown skip list as unknown', () => {
    expect(describeScanCoverage(completed([]), 'baseline').observed.join(' ')).toContain('기본 제외 경로(.git, node_modules, .venv) 외에 제외한 경로를 보고하지 않았습니다');
    const ignored = describeScanCoverage(completed([], ['paths_excluded_by_ignore_rules']), 'baseline');
    expect(ignored.observed.join(' ')).toContain('검사하지 않은 경로가 있습니다');
    expect(ignored.observed.join(' ')).not.toContain('제외한 경로를 보고하지 않았습니다');
    expect(describeScanCoverage(completed([], ['paths_excluded_by_size_limit']), 'baseline').observed.join(' ')).toContain('크기 제한');
    for (const code of ['skipped_paths_not_collected', 'skipped_paths_unverified']) {
      const unknown = describeScanCoverage(completed([], [code]), 'baseline');
      expect(unknown.unavailable.join(' ')).toContain('어떤 경로가 검사에서 제외됐는지 확인하지 못했습니다');
      expect(unknown.observed.join(' ')).not.toMatch(/제외한 경로를 보고하지 않았습니다|검사하지 않은 경로가 있습니다/);
    }
  });

  it('never presents a failed scan as a clean result and claims no exclusion evidence for it', () => {
    const statement = describeScanCoverage(failed(), 'baseline');
    expect(statement.outcome).toBe('not_completed');
    expect(statement.findingsMeaning).toContain('후보가 없다는 결과로 볼 수 없습니다');
    expect(statement.observed.join(' ')).toContain('설정된 검사가 실제로 실행됐는지 알 수 없습니다');
    expect(statement.observed.join(' ')).not.toMatch(/오류 없이|제외한 경로를 보고하지 않았습니다/);
  });

  it('keeps a zero result from a partial scan explicitly incomplete', () => {
    const statement = describeScanCoverage(partial([]), 'baseline');
    expect(statement.outcome).toBe('partial');
    expect(statement.findingsMeaning).toContain('빠진 부분에 문제가 있을 수 있고');
  });

  it.each([null, 'custom-team-rules', 'toString', '__proto__'])('assumes nothing about the rules of profile %s', (profile) => {
    const statement = describeScanCoverage(completed([]), profile);
    expect(statement.configured).toBeNull();
    expect(statement.notCovered).toBeNull();
    expect(allText(statement)).not.toMatch(/eval|dangerouslySetInnerHTML|Firestore|기본 제공 규칙 파일 기준/);
  });

  it.each([
    ['completed with findings', completed([finding])], ['completed, zero findings', completed([])],
    ['ignore-rule exclusion', completed([], ['paths_excluded_by_ignore_rules'])], ['skip list unknown', completed([], ['skipped_paths_not_collected'])],
    ['partial', partial([])], ['failed', failed()],
  ] as const)('makes no unsupported claim: %s', (_name, scan) => {
    for (const profile of [...Object.keys(BUILT_IN_PROFILE_SCOPES), 'custom']) {
      const text = allText(describeScanCoverage(scan, profile));
      for (const claim of UNSUPPORTED) expect(text, `${profile}: ${claim}`).not.toContain(claim);
    }
  });
});

describe('scan coverage in the results view', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
  const json = (data: unknown) => new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  async function show(response: ScanResponse, profile = { id: 'baseline', label: '기본 규칙', experimental: false }, heading = '정상 완료') {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
      if (url.endsWith('/options')) return json({ targets: [{ id: 'local-project', label: 'Local Project' }], rule_profiles: [profile] });
      if (url.endsWith('/scans')) return json(response);
      throw new Error('unexpected request');
    });
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-coverage-token');
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    await screen.findByRole('heading', { name: heading });
    return screen.getByRole('region', { name: '이번 검사의 범위' });
  }

  it('shows the configured scope as configuration and keeps details closed when there are findings', async () => {
    const region = await show(completed([finding]));
    expect(region).toHaveTextContent('3가지 코드 형태만 찾도록 설정돼 있습니다');
    expect(region).toHaveTextContent('설정 기준 · 실행 확인 아님');
    expect(region).toHaveTextContent('규칙 모음에 없는 문제는 목록에 나오지 않습니다');
    expect(region.querySelector('details')?.open).toBe(false);
    // UX-P0 guidance is still there.
    expect(within(screen.getByLabelText('선택한 Finding 상세')).getByRole('region', { name: '이 항목에서 할 일' })).toBeInTheDocument();
  });

  it('opens the details for zero findings and names what the profile does not cover', async () => {
    const region = await show(completed([]));
    expect(region.querySelector('details')?.open).toBe(true);
    expect(region).toHaveTextContent('앱이 안전하다는 뜻이 아닙니다');
    expect(region).toHaveTextContent('로그인·권한 확인');
    expect(region).toHaveTextContent('비밀정보');
    expect(region).toHaveTextContent('의존성');
    expect(screen.getByRole('heading', { name: '발견 항목이 없습니다' })).toBeInTheDocument();
    for (const claim of UNSUPPORTED) expect(document.body).not.toHaveTextContent(claim);
  });

  it('does not show a failed zero-finding scan as a clean result', async () => {
    const region = await show(failed(), undefined, '실행 실패');
    expect(screen.queryByRole('heading', { name: '발견 항목이 없습니다' })).toBeNull();
    expect(screen.getByRole('heading', { name: '검사가 완료되지 않았습니다' })).toBeInTheDocument();
    expect(region).toHaveTextContent('후보가 없다는 결과로 볼 수 없습니다');
    expect(region.querySelector('details')?.open).toBe(true);
  });

  it('does not show a partial zero-finding scan as a clean result', async () => {
    await show(partial([]), undefined, '부분 검사');
    expect(screen.queryByRole('heading', { name: '발견 항목이 없습니다' })).toBeNull();
    expect(screen.getByRole('heading', { name: '일부만 완료된 검사입니다' })).toBeInTheDocument();
  });

  it('uses neutral wording for a profile it does not know', async () => {
    const region = await show(completed([]), { id: 'custom-team-rules', label: '팀 규칙', experimental: false });
    expect(region).toHaveTextContent('선택한 규칙 모음(팀 규칙)이 무엇을 찾도록 설정됐는지 이 화면에서 확인할 수 없습니다');
    expect(region).toHaveTextContent('기본 제공 규칙과 같다고 가정하지 않습니다');
    expect(region).not.toHaveTextContent('eval');
  });
});
