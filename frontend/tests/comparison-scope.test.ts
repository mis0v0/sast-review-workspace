import { describe, expect, it } from 'vitest';
import type { ScanResponse } from '../src/api/types';
import { absenceScopeStatement, ruleContentState, ruleContentStatement, scanScope } from '../src/features/scans/comparisonScope';
import type { ScanContext } from '../src/features/scans/markdownExport';

const scan = (limitations: string[]): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 0,
  displayed_finding_count: 0, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  issues: [], findings: [], limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof', ...limitations],
});

describe('비교 미관찰 Finding의 검사 범위 진술', () => {
  it.each([
    [[], 'none_reported', false, false],
    [['paths_excluded_by_ignore_rules'], 'excluded', true, false],
    [['paths_excluded_by_size_limit'], 'excluded', false, true],
    [['paths_excluded_by_ignore_rules', 'paths_excluded_by_size_limit'], 'excluded', true, true],
    [['skipped_paths_not_collected'], 'unknown', false, false],
    [['skipped_paths_unverified'], 'unknown', false, false],
    // Contradictory evidence: an exclusion claim next to an unverified skip list is not trusted.
    [['paths_excluded_by_ignore_rules', 'skipped_paths_unverified'], 'unknown', true, false],
  ])('%j → %s', (limitations, evidence, ignoreRules, sizeLimit) => {
    expect(scanScope(scan(limitations))).toEqual({ evidence, ignoreRules, sizeLimit });
  });

  it('제외가 보고되지 않으면 제외 원인만 근거 없음으로 말하고 다른 원인은 남겨 둔다', () => {
    const statement = absenceScopeStatement(scan([]), '현재 검사');
    expect(statement).toContain('제외한 경로가 없다고 보고했습니다');
    expect(statement).toContain('파일 제외를 원인으로 볼 근거는 없지만');
    expect(statement).toContain('코드 수정, 파일 삭제·이동, 규칙 매치 변화');
  });

  it('제외가 있으면 어떤 파일인지 모른다고 밝히고 파일 단위 조사로 안내한다', () => {
    const statement = absenceScopeStatement(scan(['paths_excluded_by_ignore_rules', 'paths_excluded_by_size_limit']), '현재 검사');
    expect(statement).toContain('무시 규칙(.semgrepignore 또는 Semgrep 기본 제외)과 파일 크기 제한(1,000,000바이트)으로 일부 경로를 제외했습니다');
    expect(statement).toContain('어떤 파일이 제외됐는지 알 수 없습니다');
    expect(statement).toContain('소멸 근거 조사');
  });

  it('제외 정보가 없거나 모순되면 판단할 수 없다고 말한다', () => {
    for (const limitations of [['skipped_paths_not_collected'], ['paths_excluded_by_ignore_rules', 'skipped_paths_unverified']]) {
      const statement = absenceScopeStatement(scan(limitations), '기준 검사');
      expect(statement).toContain('기준 검사의 제외 경로 정보를 확인할 수 없어');
      expect(statement).toContain('판단할 수 없습니다');
      expect(statement).not.toContain('제외했습니다');
    }
  });

  it('어떤 상태에서도 수정·해결을 주장하지 않는다', () => {
    for (const limitations of [[], ['paths_excluded_by_ignore_rules'], ['skipped_paths_not_collected']]) {
      expect(absenceScopeStatement(scan(limitations), '현재 검사')).not.toMatch(/해결됐|해결되었|수정됐|수정되었|수정 완료|해결 완료|안전/);
    }
  });
});

describe('비교 규칙 파일 내용 진술', () => {
  const context = (ruleContentToken?: string | null): ScanContext => ({
    targetId: 'project-a', targetLabel: 'Project A', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false,
    scanStatus: 'completed', receivedAt: '2026-11-01T00:00:00.000Z', serverInstanceId: 'test-server-instance-01', ruleContentToken,
  });
  const a = 'A'.repeat(22);
  const b = 'B'.repeat(22);

  it.each([
    [a, a, 'same'],
    [a, b, 'different'],
    [undefined, a, 'unknown'],
    [a, null, 'unknown'],
    [null, null, 'unknown'],
    // Malformed or mismatched-format tokens are not trusted as evidence of equality or difference.
    ['short', 'short', 'unknown'],
    [a, `${a}x`, 'unknown'],
  ])('%s / %s → %s', (before, after, expected) => {
    expect(ruleContentState(context(before), context(after))).toBe(expected);
  });

  it('같은 규칙도 수정의 증거로, 다른 규칙도 확정 원인으로 말하지 않는다', () => {
    // ER-D6 item 4: when the state was observed, and what a failure means.
    for (const state of ['same', 'different'] as const) expect(ruleContentStatement(state)).toContain('실행 직전과 직후에 확인한 선택 규칙 파일의 바이트');
    expect(ruleContentStatement('same')).toContain('규칙 파일 변경을 Finding 차이의 원인으로 볼 근거는 없지만');
    // Equal bytes are not loaded-rule identity, equal detection, or remediation.
    expect(ruleContentStatement('same')).toContain('Semgrep이 실제로 로드한 규칙이나 탐지 동작이 같다는 증명은 아니며');
    expect(ruleContentStatement('same')).toContain('코드 수정이나 취약점 해결의 증거도 아닙니다');
    expect(ruleContentStatement('same')).not.toMatch(/실행됐습니다|로드했습니다|동일하게 탐지/);
    expect(ruleContentStatement('different')).toContain('규칙 변경 때문일 수 있으며');
    expect(ruleContentStatement('different')).toContain('같은 규칙으로 두 검사를 다시 실행');
    expect(ruleContentStatement('unknown')).toContain('확인할 수 없습니다');
    expect(ruleContentStatement('unknown')).toContain('조사 모드 검사였거나, 검사 중 규칙 파일이 바뀌었거나');
    for (const state of ['same', 'different', 'unknown'] as const) {
      expect(ruleContentStatement(state)).not.toMatch(/해결됐|해결되었|수정됐|수정되었|수정 완료|해결 완료/);
    }
  });
});
