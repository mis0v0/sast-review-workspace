# Scan coverage statements and launcher shutdown (A8-R1)

Two defects found in the A8 acceptance run are fixed here.

- **D1.** A normal scan reported `completed`, and the CLI reported `paths_skipped: false`, while Semgrep had left out files under `dist/`, `test/` or matching `*.min.js`. The investigation run of the same project reported `partial`.
- **D2.** Ctrl+C on the one-project launcher printed a Python traceback and exited with code 130.

## D1: what a scan says about excluded paths

### Cause

Semgrep lists the paths it left out only when run with `--verbose`. Only the investigation run passed that option. A normal scan therefore never saw the list, and the CLI derived `paths_skipped` from an issue code that could not occur: "not collected" was printed as `false`.

### Change

Every scan now asks Semgrep for its skip list, and every result carries a coverage summary: an evidence state and counts, never path names.

| Evidence state | Meaning | CLI `coverage.paths_skipped` | API limitation code |
| --- | --- | --- | --- |
| `observed`, nothing left out | Only the adapter's own exclusions (`.git`, `node_modules`, `.venv`) were skipped | `false` | none |
| `observed`, ignore rules | Paths matched Semgrep's default ignore list or the project's `.semgrepignore` | `true` | `paths_excluded_by_ignore_rules` |
| `observed`, size limit | Files above Semgrep's 1,000,000-byte limit, of any type | `true` | `paths_excluded_by_size_limit` |
| `unverified` | A skip list was reported but failed validation: an unrecognized reason, or a malformed or out-of-root entry | `null` | `skipped_paths_unverified` |
| `not_collected` | No skip list was reported | `null` | `skipped_paths_not_collected` |

`scan_status` keeps describing execution, and a normal scan's status does not depend on the skip list, as before. A `completed` scan can carry a coverage code. Parser errors, skipped rules and "no files scanned" still make a scan `partial`.

The investigation run is unchanged: any exclusion beyond the adapter's own still makes it `partial`, and comparison stays `INCOMPARABLE`. It now carries the same coverage codes as the normal scan, so both modes state the same fact about the same project. They differ only in that the investigation run, whose results back comparison claims, additionally refuses to call such a scan complete.

Contract changes:

- **CLI JSON** `schema_version` is `1.1`. `coverage.paths_skipped` can be `null` and can be `true` on a completed scan. `coverage.skipped_paths` holds `evidence`, `excluded_by_ignore_rules` and `excluded_by_size_limit`. Text and review output gain `Coverage:` / `검사 범위:` lines. Exit codes are unchanged.
- **API** `ScanResponse.limitations` gains the four codes above. No field was added and no path is exposed. The dashboard lists the codes in its existing "검사 문제와 다음 조치" panel and in the Markdown export. Rebuild the dashboard after updating: an older build rejects the new codes.
- **Scope evidence** accepts one more validated skip reason, `exceeded_size_limit`. Every other reason stays unrecognized and fails closed.

### Bounded fallback

Semgrep lists an ignored folder once per direct child, and files matched one by one (for example `*.min.js`) separately, each with its full path. Roughly ten thousand entries (fewer with long paths) exceed the 2 MB output bound, and the scan would fail where it used to succeed. A normal scan then runs once more without the list, inside the same time limit, and reports `not_collected`. The investigation run does not fall back and fails with `semgrep_output_limit`, as before.

A Semgrep without `--verbose` scans as before and reports `not_collected`.

### Measured (Semgrep 1.182.1, macOS arm64)

| Project | Normal scan before | Normal scan after | Investigation, before and after |
| --- | --- | --- | --- |
| Source plus `dist/`, `test/`, `*.min.js` | `completed`, `paths_skipped: false` | `completed`, `true`, 3 by ignore rules | `partial` |
| Nothing excluded | `completed`, `false` | `completed`, `false` (observed) | `completed` |
| Ignored files and three files over 1 MB | `completed`, `false` | `completed`, `true`, 5 by ignore rules, 3 by size | `partial` |
| One unparsable file | `partial`, `false` | `partial`, `null` (`unverified`) | `partial` |
| 12,000 ignored files in one folder | `completed`, `false` | `completed`, `null` (`not_collected`) | `output_limit_exceeded` |

Findings are identical before and after in every row. The option adds about 1–2 KB of output and no measurable time (5 interleaved runs: medians within run-to-run noise). The fallback row costs one extra Semgrep run: 8.1 s to 12.6 s.

### Alternatives rejected

- **Report `null` without collecting the list.** Truthful, but every scan would carry the same notice and none would say that `test/` was left out.
- **Collect the list and keep the existing rule in normal scans** (any exclusion makes the scan `partial`). Most real projects have a `test/` folder or a file over 1 MB, so most scans would become `partial`, which blocks comparison and discards a rescan when review work exists.
- **Make ignore-rule exclusions non-partial in the investigation run too.** That would let a project `.semgrepignore` that hides a finding produce a `COMPARABLE` result. Existing tests pin that no such outcome is reported, so this is a separate decision.

### Limits

- Counts only. Which paths were excluded is not shown.
- When any file fails to parse, Semgrep's skip list contains an entry this tool does not store, so the state is `unverified` and no counts are given.
- A coverage code on the current scan does not block the dashboard's comparison. A finding that disappears because its file became ignored is still shown as "baseline only"; the code is the hint.
- Only Semgrep 1.182.1 was exercised.

## D2: stopping the launcher

uvicorn handles Ctrl+C itself and then re-raises the signal. `uvicorn.run()` absorbs that; the one-project launcher called `Server.run()` directly and did not. The launcher's tests stopped it with SIGTERM, which does not take that path.

Ctrl+C now prints `Stopped.` and exits with code 0, like the environment-variable mode. Ctrl+C before the server is running (for example during the Semgrep check) exits with code 130 and no traceback, and the Semgrep process is stopped. Only `KeyboardInterrupt` is treated this way: any other exception still propagates, and a server that returns without starting is reported as `server_start_failed` with exit code 2.

## Verification

- `tests/test_scan_coverage_integrity.py` uses the real Semgrep subprocess for default exclusions, a custom `.semgrepignore`, adapter exclusions, gitignored source, the size limit, a parser failure, no supported files, the output bound, normal-versus-investigation consistency, comparison outcomes and the CLI. Stand-in engine output covers missing, malformed and unrecognized skip metadata and a timeout.
- `tests/test_local_launcher.py` sends SIGINT to the launcher's process group as a terminal does, with and without a pseudo-terminal, during the Semgrep check, and in environment-variable mode.
- Both sets fail on the previous `main`.
