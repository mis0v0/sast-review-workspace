import type { ScanResponse } from '../../api/types';

/**
 * What one scan's coverage statement may say, kept apart by how it is known.
 *
 * - configured: what the built-in rule profile is set up to look for. This is
 *   configuration metadata from the shipped rule files, not proof that each rule
 *   ran on each relevant file. A test ties it to the production rule files.
 * - observed: facts the API response itself reports for this scan.
 * - unavailable: coverage facts this API does not provide, stated as unknown.
 * - notCovered: security categories outside the configured profile.
 */
export interface BuiltInProfileScope {
  /** Rule file under rules/, as in the server's RULE_PROFILES. */
  ruleFile: string;
  /** Rule ids in that file; a test fails if they drift. */
  ruleIds: readonly string[];
  targets: string;
  checks: readonly string[];
  notCovered: readonly string[];
}

const OUTSIDE_EVERY_BUILT_IN_PROFILE = [
  '로그인·권한 확인(다른 사용자의 데이터에 접근할 수 있는지 등)',
  '코드나 설정에 들어 있는 비밀정보(API 키, 비밀번호 등)',
  '사용하는 패키지(의존성)의 알려진 취약점',
  '서버·배포 환경 설정과 실제로 배포된 앱의 상태',
] as const;

export const BUILT_IN_PROFILE_SCOPES: Readonly<Record<string, BuiltInProfileScope>> = {
  baseline: {
    ruleFile: 'security-baseline.yml',
    ruleIds: ['baseline.javascript-dynamic-eval', 'baseline.react-dangerous-html', 'baseline.firestore-unconditional-write'],
    targets: 'JavaScript·TypeScript 파일과 Firestore 보안 규칙 파일',
    checks: [
      'eval, new Function 같은 동적 코드 실행',
      'React의 dangerouslySetInnerHTML 사용',
      'Firestore 규칙에서 조건 없이(if true) 쓰기를 허용하는 선언',
    ],
    notCovered: [...OUTSIDE_EVERY_BUILT_IN_PROFILE, 'SQL·명령어 주입 등 위 세 가지가 아닌 취약점 유형', 'JavaScript·TypeScript와 Firestore 규칙이 아닌 언어와 파일'],
  },
  'eval-experimental': {
    ruleFile: 'experimental/javascript-eval-taint.yml',
    ruleIds: ['experimental.javascript-eval-taint', 'experimental.javascript-eval-taint-with-synthetic-sanitizer'],
    targets: 'JavaScript·TypeScript 파일',
    checks: ['규칙이 정의한 요청 값이 eval까지 전달되는 흐름(실험용 규칙)'],
    notCovered: [...OUTSIDE_EVERY_BUILT_IN_PROFILE, 'eval로의 값 전달이 아닌 다른 취약점 유형', 'JavaScript·TypeScript가 아닌 언어와 파일'],
  },
  'command-injection-experimental': {
    ruleFile: 'experimental/javascript-command-injection-taint.yml',
    ruleIds: ['experimental.javascript-command-injection-taint'],
    targets: 'JavaScript·TypeScript 파일',
    checks: ['규칙이 정의한 요청 값이 Node.js 셸 명령 문자열로 전달되는 흐름(실험용 규칙)'],
    notCovered: [...OUTSIDE_EVERY_BUILT_IN_PROFILE, '셸 명령 주입이 아닌 다른 취약점 유형', 'JavaScript·TypeScript가 아닌 언어와 파일'],
  },
};

export interface ScanCoverageStatement {
  /** null when the profile is not a known built-in one: nothing is assumed about its rules. */
  configured: { targets: string; checks: readonly string[] } | null;
  outcome: 'completed' | 'partial' | 'not_completed';
  observed: string[];
  unavailable: string[];
  notCovered: readonly string[] | null;
  findingsMeaning: string;
}

export function describeScanCoverage(scan: ScanResponse, ruleProfileId: string | null): ScanCoverageStatement {
  const scope = ruleProfileId !== null && Object.hasOwn(BUILT_IN_PROFILE_SCOPES, ruleProfileId) ? BUILT_IN_PROFILE_SCOPES[ruleProfileId] : undefined;
  const outcome = scan.scan_status === 'completed' && scan.completed ? 'completed' : scan.scan_status === 'partial' ? 'partial' : 'not_completed';
  const has = (code: string) => scan.limitations.includes(code);
  const observed: string[] = [];
  const unavailable: string[] = ['검사한 파일 수와, 각 규칙이 실제로 어떤 파일에 적용됐는지는 이 화면에 제공되지 않습니다.'];

  if (outcome === 'completed') observed.push(`검사 도구${scan.semgrep_version ? `(Semgrep ${scan.semgrep_version})` : ''}가 오류 없이 끝났다고 보고했습니다.`);
  else if (outcome === 'partial') observed.push('검사 도구가 문제를 보고해, 일부 파일이나 규칙의 결과가 빠졌을 수 있습니다.');
  else observed.push('검사가 완료되지 않았습니다. 설정된 검사가 실제로 실행됐는지 알 수 없습니다.');

  if (outcome !== 'not_completed') {
    if (has('skipped_paths_not_collected') || has('skipped_paths_unverified')) {
      unavailable.push('어떤 경로가 검사에서 제외됐는지 확인하지 못했습니다.');
    } else {
      if (has('paths_excluded_by_ignore_rules')) observed.push('제외 규칙(.semgrepignore 또는 Semgrep 기본 제외)에 따라 검사하지 않은 경로가 있습니다. 경로 이름은 표시하지 않습니다.');
      if (has('paths_excluded_by_size_limit')) observed.push('크기 제한(1MB)을 넘어 검사하지 않은 파일이 있습니다.');
      if (!has('paths_excluded_by_ignore_rules') && !has('paths_excluded_by_size_limit')) observed.push('Semgrep은 기본 제외 경로(.git, node_modules, .venv) 외에 제외한 경로를 보고하지 않았습니다.');
    }
  }
  if (scan.omitted_finding_count > 0) observed.push(`보고된 후보 ${scan.finding_count}건 중 ${scan.omitted_finding_count}건은 화면에 표시되지 않았습니다.`);
  if (scope) unavailable.push('이 설명은 기본 제공 규칙 파일 기준입니다. 서버의 규칙 파일이 수정됐다면 실제 검사와 다를 수 있습니다.');

  let findingsMeaning: string;
  if (outcome === 'not_completed') findingsMeaning = '검사가 완료되지 않았으므로, 후보가 없다는 결과로 볼 수 없습니다.';
  else if (scan.finding_count === 0) findingsMeaning = outcome === 'partial'
    ? '일부만 완료된 검사에서 후보가 보고되지 않았습니다. 빠진 부분에 문제가 있을 수 있고, 앱이 안전하다는 뜻이 아닙니다.'
    : '설정된 형태의 코드가 보고되지 않았다는 뜻입니다. 규칙 모음에 없는 문제나 검사되지 않은 경로까지 확인한 것은 아니므로, 앱이 안전하다는 뜻이 아닙니다.';
  else findingsMeaning = '아래 후보는 설정된 형태와 일치한 코드이며, 규칙 모음에 없는 문제는 목록에 나오지 않습니다.';

  return {
    configured: scope ? { targets: scope.targets, checks: scope.checks } : null,
    outcome,
    observed,
    unavailable,
    notCovered: scope ? scope.notCovered : null,
    findingsMeaning,
  };
}
