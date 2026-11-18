# Rule content drift in the normal comparison (A8-R3)

## Reproduced gap

Each rule profile names one rule file in the trusted rules directory (`RULE_PROFILES`). Semgrep reads that file from disk on every scan; nothing pins its content. The normal comparison requires the same server process, target, profile ID and Semgrep version, but no part of a v1 scan response identified the rule content.

Reproduction with real FastAPI and Semgrep 1.182.1, one server process and byte-identical target code:

| | Scan 1 | Scan 2 |
| --- | --- | --- |
| Rule file | original | same rule ID, plus a rule-level `paths.exclude: [app.js]` |
| Status, Semgrep, server instance, profile | completed, 1.182.1, same, `baseline` | the same |
| Findings | `baseline.javascript-dynamic-eval` in `app.js:3` | none |
| Coverage codes | none | none |

The comparison was eligible. The finding was listed as observed only in the baseline scan, and A8-R2's scope note truthfully reported that Semgrep excluded nothing beyond the defaults: Semgrep does not list rule-level path filters as skipped paths. Nothing showed that the rule had changed.

Realistic triggers include tuning a rule, or a `git pull` or branch switch of the rules, while the dashboard stays open against one server process. A server restart already blocks the comparison (A6).

## Decision

After every normal scan, the server returns `X-Rule-Content-Token`: an opaque random token for the bytes of the selected rule file.
- Within one server process and profile, equal tokens mean identical bytes. Restoring the bytes restores the token.
- **How the bytes are pinned:** the file is hashed immediately before and after the Semgrep run, and only an unchanged digest gets a token. A file edited during the run, or one that cannot be read safely, gets none.
- **Bounded memory:** at most 64 distinct contents are remembered per process, and later ones get no token. Nothing is ever evicted, so a token is never reused for different bytes.
- **Digest stays private:** the digest never leaves the server. This follows ER-D6, which keeps rule digests out of the API, logs and exports, and names digest-free closed states as the public form.

The dashboard keeps the token in the scan context alongside `serverInstanceId`. Like that field, it is not exported. The comparison derives one closed state:

| State | When | Statement (panel and export) |
| --- | --- | --- |
| `same` | Both tokens valid and equal | Same rule bytes. There is no evidence that a rule change caused the difference, and this is not evidence of a fix. |
| `different` | Both valid, not equal | The rule content differs under the same profile. The difference may come from the rule change rather than the code, and this comparison cannot separate the two. Rescan both with the same rules to see code changes. The summary line shows "규칙 내용 다름" (rule content differs). |
| `unknown` | Either side missing or malformed | Rule equality cannot be determined. A rule change may be the cause. |

Comparison eligibility is unchanged. The export records only the label (같음 / 다름 / 확인 불가) and the statement.

### Alternatives rejected

- **Return the SHA-256 in the body or a header.** This contradicts ER-D6. A body field would also silently change `investigation-scan/v1`, which embeds `ScanResponse` and is versioned.
- **Block the comparison when rules differ.** Comparing two rule versions on the same code is a legitimate rule-tuning task, and blocking would hide its result.
- **A generic "rules may differ" note with no evidence.** This could not tell a genuine fix from drift, and every comparison would carry the same caveat.
- **Generalise investigation mode's private rule copy to all profiles.** That copy is restricted to the baseline file on purpose (ER-D6/D7), and a before-and-after digest is enough for a comparison statement.
- **Restart or invalidate the server when rules change.** Heavier, and it turns a statement into a block.

## Validation

**Python** (`tests/test_rule_content_token.py`):
- With real Semgrep:
  - a changed rule behind the same ID changes the token, while Semgrep reports no skipped path;
  - restoring the bytes restores the token;
  - a genuine code fix with unchanged rules keeps the token;
  - a comment-only edit and an added rule each change it.
- With a stand-in engine: a file edited during the run, or removed, gets no token; the token table is bounded and never evicts.
- A service without token support sends no header.
- The header is exposed through CORS, and the token never contains the digest.

**Vitest:**
- every state, including one side missing and malformed tokens;
- the panel driven through `fetch` response headers (summary flag, notes, comparison still available, token not shown);
- the export (label and statement, token absent).

**Real Chromium, FastAPI and Semgrep** (`real-disappearance-scope.spec.ts`): the A8-R2 comparison now states "same bytes". The spec then edits the harness rule copy (same rule ID, rule-level path filter), rescans, and checks:
- the coverage codes are unchanged;
- the summary shows "규칙 내용 다름" and the note says the content differs;
- the export reads "규칙 파일 내용: 다름".

The rule file is restored in a `finally` block.

**Mutation checks:** hashing only after the run, treating a missing token as `same`, and removing the summary flag each fail the tests.

**Existing tests that assumed the route calls `scan`:** the v1 route now calls `scan_with_rule_content_token`, which affected two tests in `tests/test_api_security.py`.
- `test_internal_error_is_sanitized…` failed, because its patch no longer intercepted the call.
- `test_rejected_header_matrix_never_calls_scan_service` would have **passed vacuously** for the same reason.

Both now patch every scan entry point, and the second gained a positive control: one accepted request must reach the recorder. The exact CORS expose-header assertion now lists the new header.

## Limits

- **The token tracks bytes, not detection semantics.** A comment-only edit reports `different` (a conservative false alarm), and a semantically equivalent rewrite does too.
- **One server process only.** Tokens mean nothing across restarts, which the comparison already blocks.
- **Only the selected rule file.** Semgrep is given exactly that one file. Engine options are constant in code, and the Semgrep version is compared separately.
- **An edit made and reverted entirely between the two hashes** of a single run is not detected.
- **Investigation runs carry no token,** so their normal-comparison note says `unknown`. For the baseline profile, the investigation panel's rule-bytes result remains the authority.
- **Older dashboards** ignore the header and treat rule content as unknown.
