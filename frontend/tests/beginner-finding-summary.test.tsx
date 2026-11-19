import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ApiFinding, FindingKind, ScanResponse } from '../src/api/types';
import { App } from '../src/app/App';
import { getFindingReviewGuidance, hasKnownRuleGuidance } from '../src/features/scans/reviewGuidance';

const options = { targets: [{ id: 'target-a', label: '합성 프로젝트' }], rule_profiles: [{ id: 'baseline', label: '기본 규칙', experimental: false }] };
const finding = (ruleId: string, kind: FindingKind = 'pattern'): ApiFinding => ({ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: ruleId, severity: 'high', verification_status: 'unverified', finding_kind: kind, file_path: 'src/handler.js', line_number: 2, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null });
const scan = (findings: ApiFinding[]): ScanResponse => ({ scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'] });
const json = (data: unknown) => new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
const TOKEN = 'synthetic-beginner-token';

async function scanWith(response: ScanResponse) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
    if (url.endsWith('/options')) return json(options);
    if (url.endsWith('/scans')) return json(response);
    throw new Error('unexpected request');
  });
  const user = userEvent.setup(); render(<App/>);
  await screen.findByText('API 연결됨');
  await user.type(screen.getByLabelText('로컬 API 토큰'), TOKEN);
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByRole('heading', { name: '정상 완료' });
}

// Words that would turn a candidate or a disappearance into a verdict.
const VERDICTS = ['안전합니다', '안전한 코드', '수정됐습니다', '수정되었습니다', '해결됐습니다', '해결되었습니다', '취약점입니다', '취약점이 있습니다'];
const BASELINE_RULE_IDS = [...readFileSync(resolve(process.cwd(), '../rules/security-baseline.yml'), 'utf8').matchAll(/^ {2}- id: (\S+)$/gm)].map((m) => m[1]);

describe('beginner guidance content', () => {
  it('covers every rule in the baseline profile, so no baseline finding falls back to generic text', () => {
    expect(BASELINE_RULE_IDS.length).toBeGreaterThan(0);
    for (const id of BASELINE_RULE_IDS) expect(hasKnownRuleGuidance(id), id).toBe(true);
  });

  it.each([...BASELINE_RULE_IDS.map((id) => [id, 'pattern'] as const), ['unknown.rule', 'pattern'] as const, ['unknown.rule', 'taint'] as const, ['unknown.rule', 'unclassified'] as const])(
    'gives %s (%s) an impact, actions, and no verdict wording', (ruleId, kind) => {
      const guidance = getFindingReviewGuidance(ruleId, kind);
      expect(guidance.impact.length).toBeGreaterThan(20);
      expect(guidance.actions.length).toBeGreaterThan(0);
      const text = [guidance.finding, guidance.impact, ...guidance.actions].join(' ');
      for (const verdict of VERDICTS) expect(text).not.toContain(verdict);
    });

  it('states impacts conditionally rather than as confirmed outcomes', () => {
    for (const id of BASELINE_RULE_IDS) expect(getFindingReviewGuidance(id, 'pattern').impact).toMatch(/다면|수 있습니다/);
  });
});

describe('beginner finding summary in the finding detail', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it('shows what was detected, the conditional impact, the fix direction, what is unverified and what a rescan does not prove, without expanding anything', async () => {
    await scanWith(scan([finding('baseline.javascript-dynamic-eval')]));
    const detail = screen.getByLabelText('선택한 Finding 상세');
    const summary = within(detail).getByRole('region', { name: '이 항목에서 할 일' });
    expect(summary.closest('details')).toBeNull();
    expect(summary).toHaveTextContent('검사 도구가 보고함');
    expect(summary).toHaveTextContent('확인할 파일과 위치');
    expect(detail).toHaveTextContent('src/handler.js:2');
    expect(summary).toHaveTextContent('조건부 · 확인 안 됨');
    expect(summary).toHaveTextContent('외부에서 온 값');
    expect(summary).toHaveTextContent('JSON 파싱');
    expect(summary).toHaveTextContent('이 검사로 확인되지 않았습니다');
    expect(summary).toHaveTextContent('이 항목이 더 이상 보이지 않아도 수정이 확인된 것은 아닙니다');
    expect(summary).toHaveTextContent('기존 기능이 그대로 동작하는지');
    for (const verdict of VERDICTS) expect(summary).not.toHaveTextContent(verdict);
    expect(detail).not.toHaveTextContent(TOKEN);
    // The existing analyst guidance and limits stay in place.
    expect(within(detail).getByRole('region', { name: '분석가 검토 가이드' })).toBeInTheDocument();
    expect(detail).toHaveTextContent('실제 취약점으로 확정되지 않았습니다');
  });

  it('falls back to generic, non-specific guidance for a rule it does not know', async () => {
    await scanWith(scan([finding('custom.rule', 'unclassified')]));
    const summary = within(screen.getByLabelText('선택한 Finding 상세')).getByRole('region', { name: '이 항목에서 할 일' });
    expect(summary).toHaveTextContent('가능한 영향을 설명하지 않습니다');
    expect(summary).not.toHaveTextContent('JSON 파싱');
  });

  it('renders an untrusted file path as text', async () => {
    await scanWith(scan([{ ...finding('baseline.react-dangerous-html'), file_path: 'src/<img src=x onerror=alert(1)>.jsx' }]));
    const detail = screen.getByLabelText('선택한 Finding 상세');
    expect(within(detail).getByRole('region', { name: '이 항목에서 할 일' })).toBeInTheDocument();
    expect(detail.querySelector('img')).toBeNull();
    expect(detail).toHaveTextContent('src/<img src=x onerror=alert(1)>.jsx:2');
  });

  it('shows no finding summary for a scan without findings and keeps the no-guarantee message', async () => {
    await scanWith(scan([]));
    expect(screen.queryByRole('region', { name: '이 항목에서 할 일' })).toBeNull();
    expect(screen.getByText(/검사되지 않은 문제까지 안전하다는 뜻은 아닙니다/)).toBeInTheDocument();
  });
});
