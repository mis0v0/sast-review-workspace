import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ScanStatusGuidance } from '../src/app/BeginnerGuidance';
import { createReviewMarkdown, type ScanContext } from '../src/features/scans/markdownExport';
import { compareScanSnapshots } from '../src/features/scans/compare';
import type { ApiFinding, ScanResponse } from '../src/api/types';

const finding: ApiFinding = {
  finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.javascript-dynamic-eval', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern',
  file_path: 'src/app.js', line_number: 2, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
};
const baseLimitations = ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'];
const completed = (coverage: string[]): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], findings: [finding], limitations: [...baseLimitations, ...coverage],
});
const context: ScanContext = { targetId: 'local-project', targetLabel: 'Local Project', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline Rules', experimental: false, scanStatus: 'completed', receivedAt: '2026-11-16T01:00:00.000Z' };

afterEach(cleanup);

describe('scan coverage on a completed scan', () => {
  it.each([
    ['paths_excluded_by_ignore_rules', '제외 규칙으로 검사하지 않은 경로가 있습니다.'],
    ['paths_excluded_by_size_limit', '크기 제한을 넘어 검사하지 않은 파일이 있습니다.'],
    ['skipped_paths_unverified', '제외된 경로를 확인하지 못했습니다.'],
    ['skipped_paths_not_collected', '제외된 경로 정보를 수집하지 못했습니다.'],
  ])('explains %s without calling the scan partial or failed', (code, title) => {
    render(<ScanStatusGuidance scan={completed([code])} />);
    expect(screen.getByText('검사 문제와 다음 조치')).toBeTruthy();
    expect(screen.getByRole('heading', { name: title })).toBeTruthy();
    expect(screen.getByText(code)).toBeTruthy();
    expect(screen.queryByLabelText('쉬운 검사 결과 설명')).toBeNull();
  });

  it('shows no coverage notice when the scan reports none', () => {
    render(<ScanStatusGuidance scan={completed([])} />);
    expect(screen.queryByText('검사 문제와 다음 조치')).toBeNull();
  });

  it('keeps two completed scans comparable when one of them excluded paths', () => {
    const instance = '5Ev81fEWTyDwMkcdGFYHNg';
    const baseline = { scan: completed([]), context: { ...context, serverInstanceId: instance } };
    const current = { scan: { ...completed(['paths_excluded_by_ignore_rules']), findings: [], finding_count: 0, displayed_finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
      context: { ...context, receivedAt: '2026-11-16T01:05:00.000Z', serverInstanceId: instance } };
    const comparison = compareScanSnapshots(baseline, current);
    expect(comparison.comparable).toBe(true);
    expect(comparison.groups?.baselineOnly.map((item) => item.file_path)).toEqual(['src/app.js']);
    // The current scan itself carries the notice that explains what may have happened.
    expect(current.scan.limitations).toContain('paths_excluded_by_ignore_rules');
  });

  it('writes the coverage statement into the Markdown report', () => {
    const markdown = createReviewMarkdown(context, completed(['paths_excluded_by_ignore_rules', 'paths_excluded_by_size_limit']));
    expect(markdown).toContain('### 검사 범위 제한');
    expect(markdown).toContain('- 제외 규칙(Semgrep 기본 목록 또는 프로젝트 .semgrepignore)에 해당하는 경로는 검사하지 않았습니다.');
    expect(markdown).toContain('- Semgrep 크기 제한(1MB)을 넘는 파일은 검사하지 않았습니다.');
  });
});
