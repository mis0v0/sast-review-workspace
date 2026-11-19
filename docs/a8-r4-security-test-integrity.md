# Security test integrity audit (A8-R4)

Question: do the security tests fail when the property they protect is broken? Method: one production mutation at a time in an isolated worktree, run against the tests that cover it, then restore and verify the original bytes. Baseline `aa75aa7`, Semgrep 1.182.1; the unmutated baseline set passed (291 tests).

## Result

34 mutations: 33 in Python and 1 in the frontend export. 21 were killed and 13 survived. Every survivor was classified, and the three candidate gaps were rerun against every test file that touches their code.

| Outcome | Mutations |
| --- | --- |
| Killed by the test for that property | Host allowlist, Origin allowlist, token check removed, `/api/v2` subpaths unprotected, `POST /api/v1/scans` unprotected, content type, duplicate headers, target preflight limits, non-regular `.semgrepignore`, target device/inode, Semgrep `--metrics=off`, `--no-git-ignore`, `--oss-only`, `GIT_DIR` isolation, private `HOME`, output cap, cross-target and same-run evidence sessions, session release, run release while referenced, rule-content token in the comparison export |
| **False pass, fixed** | Token compared as a prefix (`expected.startswith(candidate)`): every test passed, so one correct leading character would have authenticated |
| **Gap, fixed** | `Host` with userinfo (`user@testserver`) accepted: untested |
| Covered by another layer (no change) | Advertised `Content-Length` cap (the streamed body cap still returns 413); `/api/v2` preflight header allowlist (Starlette CORS also refuses); target resolve check and target symlink-component check (each catches what the other misses); service and route response caps (each backs up the other); rule-file symlink check (`is_relative_to` still refuses links outside the rules directory, and the existing test for that passes) |
| Equivalent (unreachable) | Scan-time target/rules and target/target overlap checks: path-only checks on paths the configuration already validated. Rule-bytes session expiry: an expired session is purged just before the check, because a session is pinned only during an evaluation and only one evaluation runs at a time |
| Not reachable from the API (no change) | Run expiry in `get_run`: expired records are purged first unless another read or evaluation has pinned them at that moment. A8-R5 found that no production code calls `get_run`. Even if a pinned, expired record passed the first check, the re-check after deserialising refuses it |

The correction adds near-miss cases to `test_rejected_header_matrix_never_calls_scan_service`, which already asserts that no rejected request reaches the scan service and has a positive control:
- a truncated token, a one-character token, an extended token, and one differing in its last character must all get `401 unauthorized`;
- `user@testserver` and `user:pass@testserver` must get `400 host_not_allowed`.

Both mutations now fail this test, because the mutated server returns 200 from the scan recorder.

## The shared `400 target_not_allowed`

The v1 scan maps every `OSError` and `ValueError`, including one raised by the adapter, to `400 target_not_allowed`. Tests that only check that code could pass for the wrong reason. Most boundary tests also assert that the adapter was never called (`CountingAdapter`, `MustNotScan`), and their fixtures have positive controls, so a missing rule file cannot make them pass. One test, `test_target_replacement_with_symlink_is_rejected_before_adapter`, asserts the code only. Its stand-in adapter returns a result instead of raising, so a scan that proceeded would fail the test. The combination is not a false pass.

## Browser listeners

`real-analyst-workflow.spec.ts` and `real-investigation.spec.ts` store response bodies from async listeners. Each read happens after many further awaited steps, and a missing body fails the assertion (`toHaveLength(3)`, `status` 201/200, exact body). The worst case is a rare flaky failure, never a pass, so they were not changed.

## Limits

- One mutation at a time: combined failures, such as removing both target layers, were not tested.
- Mutations were chosen by hand across the five priority areas; this is not exhaustive mutation testing.
- Concurrency (registry pins, filesystem races) was reasoned about, not exercised.
