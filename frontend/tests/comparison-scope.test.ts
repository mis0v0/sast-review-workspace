import { describe, expect, it } from 'vitest';
import type { ScanResponse } from '../src/api/types';
import { absenceScopeStatement, scanScope } from '../src/features/scans/comparisonScope';

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
