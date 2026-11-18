import type { ScanResponse } from '../../api/types';
import type { ScanContext } from './markdownExport';

/**
 * Whether two scans of one profile used the same rule file bytes, from the opaque tokens the server
 * returned. Tokens are only meaningful within one server process, which the comparison already requires.
 */
export type RuleContentState = 'same' | 'different' | 'unknown';

const RULE_CONTENT_TOKEN = /^[A-Za-z0-9_-]{22}$/;

export function ruleContentState(baseline: ScanContext, current: ScanContext): RuleContentState {
  const before = baseline.ruleContentToken;
  const after = current.ruleContentToken;
  if (typeof before !== 'string' || typeof after !== 'string' || !RULE_CONTENT_TOKEN.test(before) || !RULE_CONTENT_TOKEN.test(after)) return 'unknown';
  return before === after ? 'same' : 'different';
}

export const ruleContentLabels: Record<RuleContentState, string> = { same: '같음', different: '다름', unknown: '확인 불가' };

// ER-D6 item 4: each state says when it was observed and what a failure means. The observation is
// the selected rule file's bytes immediately before and after each Semgrep run, not the rules
// Semgrep loaded and not its detection behavior (ER-D6 item 5, `loaded_rule_identity_unverified`).
const OBSERVED = '각 검사의 실행 직전과 직후에 확인한 선택 규칙 파일의 바이트';

export function ruleContentStatement(state: RuleContentState): string {
  if (state === 'same') {
    return `두 검사에서 ${OBSERVED}가 모두 같습니다. 규칙 파일 변경을 Finding 차이의 원인으로 볼 근거는 없지만, Semgrep이 실제로 로드한 규칙이나 탐지 동작이 같다는 증명은 아니며 코드 수정이나 취약점 해결의 증거도 아닙니다.`;
  }
  if (state === 'different') {
    return `같은 규칙 프로필이지만 두 검사에서 ${OBSERVED}가 다릅니다. Finding 차이는 코드가 아니라 규칙 변경 때문일 수 있으며, 이 비교로는 둘을 구분할 수 없습니다. 주석만 바꿔도 바이트는 달라집니다. 코드 변화를 보려면 같은 규칙으로 두 검사를 다시 실행해 비교하세요.`;
  }
  return '두 검사의 선택 규칙 파일 바이트가 같은지 확인할 수 없습니다. 한쪽 결과에 규칙 파일 확인 정보가 없습니다: 조사 모드 검사였거나, 검사 중 규칙 파일이 바뀌었거나, 규칙 파일을 안전하게 읽을 수 없었거나, 서버의 기록 한도를 넘었거나, 이 정보를 제공하지 않는 서버일 수 있습니다. 규칙 변경이 Finding 차이의 원인일 수 있습니다.';
}

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
