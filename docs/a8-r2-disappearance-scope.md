# Disappeared findings and scan scope in the normal comparison (A8-R2)

## Gap

The normal comparison (two `/api/v1/scans` results compared in the browser) places a finding in "기준 검사에서만 관찰" (observed only in the baseline scan) whenever its ID is missing from the current scan. It never claimed a fix: labels and notes already say that a missing finding is not evidence of one. But it said nothing about the most common non-fix cause.

A8-R1 made every scan report whether it excluded paths, as limitation codes with counts only and no paths, and deliberately did not block comparison on them (A8-R1, "Limits"). The comparison never read those codes. As a result:
- a finding whose file became `.semgrepignore`d appeared in a comparable comparison;
- the panel and export showed only the status "정상 완료" (completed);
- the follow-up guidance suggested "code move or rule match change", but never "the file was not scanned".

Per-file evidence already exists in investigation mode (`/api/v2`, `finding_disappearance_evaluator.PathObservation`), which binds both runs and reports `PATH_EXPLICITLY_SKIPPED`, `PATH_REPORTED_SCANNED` and related states for each disappeared finding. The normal comparison never pointed there.

## Decision

The normal comparison now states, next to each group of findings seen in only one scan, what the *other* scan's own coverage report says about excluded files. The statement is built only from limitation codes the API already returns.

| Other scan reports | Evidence state | Statement |
| --- | --- | --- |
| No coverage code | `none_reported` | Nothing excluded beyond `.git`, `node_modules`, `.venv`. There is no evidence that exclusion caused the absence; code change, deletion, move or a rule-match change cannot be told apart here. |
| `paths_excluded_by_ignore_rules` and/or `paths_excluded_by_size_limit` | `excluded` | Some paths were excluded, by which mechanism, so this finding's file may not have been scanned. The view cannot tell which files. Points to investigation mode for per-file evidence. |
| `skipped_paths_not_collected` or `skipped_paths_unverified`, alone or with an exclusion code | `unknown` | Whether exclusion played a role cannot be determined. Points to investigation mode. |

- Baseline-only findings use the current scan's report; current-only findings use the baseline scan's report. Shared findings get no statement.
- One function, `features/scans/comparisonScope.ts`, produces the text for both the panel (`role="note"` in the selected group) and the Markdown export (`## 검사 범위와 미관찰 원인`), so they cannot disagree.
- Comparison eligibility is unchanged. No API field, endpoint or path disclosure was added.

### Alternatives rejected

- **Return scanned and skipped paths in v1 so the browser can classify each finding's file.** This reverses A8-R1's decision not to expose paths, and duplicates investigation mode, which binds rule bytes and scan context that v1 does not.
- **A hashed path set for membership checks.** Same duplication, and hashes of guessable paths are not truly private.
- **Block the comparison whenever the current scan excluded paths.** A8-R1 rejected this: most projects have a `test/` folder or a large file, so most comparisons would be blocked.
- **Pair a disappeared finding with a new finding from the same rule as a "possible move".** That is a heuristic that would present a guess as evidence.

## Validation

- **Unit tests** (`tests/comparison-scope.test.ts`): every code combination, including contradictory codes, which resolve to `unknown`. No statement in any state claims a fix.
- **Component test** (`tests/scan-comparison-ui.test.tsx`): the excluded statement in the baseline-only group, the none-reported statement in the current-only group, no note for shared findings, and the comparison still available.
- **Export test** (`tests/comparison-markdown-export.test.ts`): the same sentences appear in the export.
- **Real FastAPI, Semgrep 1.182.1 and Chromium:**
  - `real-disappearance-scope.spec.ts`: `hidden.js` is ignored and `kept.js` renamed between scans. The second scan is `completed` with `paths_excluded_by_ignore_rules`, and both files appear as baseline-only. The note states the exclusion without naming a file; `moved.js` is current-only with a none-reported note; the export carries the statement and no local path.
  - `real-analyst-workflow.spec.ts`: a genuinely edited file, with nothing excluded, gets the none-reported statement and still no fix claim.
- **Mutation checks:** letting an exclusion code override an unverified skip list, or removing the baseline-only note, each fail the tests.

## Limits

- **No per-file statement in the normal comparison.** When a scan excluded files, an unrelated exclusion and the finding's own file being excluded look the same here. Investigation mode is the per-file answer, and it requires running both scans in that mode.
- **Rule content is not compared.** Two scans with the same rule profile ID whose rule files were edited on disk in between remain comparable; only investigation mode compares rule bytes. The existing note already names rule changes as a possible cause.
- **Moves are not detected.** A moved file produces a baseline-only and a current-only finding; the statement names a move as a possible cause but does not link the two.
- **Partial and failed scans are still blocked** from the normal comparison, as before.
