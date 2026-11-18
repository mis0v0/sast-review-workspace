import type { ScanResponse } from '../../api/types';

/**
 * What one scan's own coverage report says about files left out of it.
 * Built only from the limitation codes the API already returns; the API
 * reports counts, never paths, so no statement here is about a specific file.
 */
export type ExclusionEvidence =
  /** Skip list observed and nothing excluded beyond the adapter's own `.git`, `node_modules`, `.venv`. */
  | 'none_reported'
  /** Skip list observed and some paths excluded by ignore rules and/or the size limit. */
  | 'excluded'
  /** Skip list missing or failed validation, or the codes contradict each other. */
  | 'unknown';

export interface ScanScope {
  evidence: ExclusionEvidence;
  ignoreRules: boolean;
  sizeLimit: boolean;
}

export function scanScope(scan: ScanResponse): ScanScope {
  const codes = new Set(scan.limitations);
  const ignoreRules = codes.has('paths_excluded_by_ignore_rules');
  const sizeLimit = codes.has('paths_excluded_by_size_limit');
  // Any doubt about the skip list wins over a claim of exclusion or of none.
  if (codes.has('skipped_paths_unverified') || codes.has('skipped_paths_not_collected')) return { evidence: 'unknown', ignoreRules, sizeLimit };
  return { evidence: ignoreRules || sizeLimit ? 'excluded' : 'none_reported', ignoreRules, sizeLimit };
}

function exclusionKinds(scope: ScanScope): string {
  return [scope.ignoreRules && '무시 규칙(.semgrepignore 또는 Semgrep 기본 제외)', scope.sizeLimit && '파일 크기 제한(1,000,000바이트)']
    .filter(Boolean).join('과 ');
}

const OTHER_CAUSES = '코드 수정, 파일 삭제·이동, 규칙 매치 변화 같은 다른 원인은 이 비교로 구분할 수 없습니다.';
const PER_FILE = '파일 단위 근거가 필요하면 조사 모드로 두 검사를 다시 실행해 "소멸 근거 조사"에서 확인하세요.';

/**
 * Why a Finding seen in only one of two scans may be missing from the other,
 * as far as that other scan's coverage report can tell. `scan` is the scan the
 * Finding is missing from: the current scan for baseline-only Findings, the
 * baseline scan for current-only Findings.
 */
export function absenceScopeStatement(scan: ScanResponse, scanName: '현재 검사' | '기준 검사'): string {
  const scope = scanScope(scan);
  if (scope.evidence === 'none_reported') {
    return `${scanName}는 기본 제외(.git, node_modules, .venv) 외에 제외한 경로가 없다고 보고했습니다. 파일 제외를 원인으로 볼 근거는 없지만, ${OTHER_CAUSES}`;
  }
  if (scope.evidence === 'excluded') {
    return `${scanName}는 ${exclusionKinds(scope)}으로 일부 경로를 제외했습니다. 이 Finding의 파일이 제외돼 관찰되지 않았을 수 있으며, 이 화면은 어떤 파일이 제외됐는지 알 수 없습니다. ${PER_FILE}`;
  }
  return `${scanName}의 제외 경로 정보를 확인할 수 없어, 파일이 검사에서 제외돼 관찰되지 않았는지 판단할 수 없습니다. ${PER_FILE}`;
}
