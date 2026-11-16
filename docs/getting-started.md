# Getting started

Full setup and usage guide. The [README](../README.en.md) has the shortest path to a first scan.

Commands run from the repository root unless noted.

## 1. Prerequisites

| Tool | Version | Check |
| --- | --- | --- |
| Python | 3.12 (`.python-version`) | `python3 --version` |
| uv | 0.11.26 (the version CI installs) | `uv --version` |
| Semgrep CLI | **1.182.1**, on `PATH` | `semgrep --version` |
| Node.js / npm | Node 24.22.2 (`.nvmrc`; `frontend/package.json` requires `>=24 <25`) | `node --version` |

Install the pinned Semgrep the same way CI does:

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
semgrep --version   # must print 1.182.1
```

Node.js is only needed for the dashboard. The CLI and API need Python, uv and Semgrep.

## 2. Install locked dependencies

```sh
uv sync --locked
uv run --locked python -m ai_code_security_analyzer --help
```

## 3. Run a sample scan (CLI)

The repository ships small positive fixtures. Copy them to a neutral directory first: scanning them in place under `tests/` returns `partial` with `no_files_scanned` (see [Troubleshooting](#troubleshooting)).

```sh
SAMPLE="$(cd "$(mktemp -d)" && pwd -P)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

Expected: `Status: completed` and `Findings: 7 unverified candidate(s)` (5 high, 2 medium).

Other formats:

```sh
# Machine-readable JSON
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format json

# Analyst review as a NEW Markdown file (refuses to overwrite an existing file)
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format review-md --output review-report.md
```

`--format` accepts `text` (default), `json`, `review` and `review-md`. `--output` is only accepted with `json` or `review-md`.

| Exit code | Meaning |
| --- | --- |
| 0 | Scan completed. Findings may still be present. |
| 1 | Partial scan or result-conversion loss. Treat findings as incomplete candidates. |
| 2 | Invalid CLI arguments, local path, or output file (including an existing `--output` file). |
| 3 | Full failure (Semgrep execution, JSON handling, or report write). |

`completed=true` means the scan finished. It does **not** mean the code is safe. Every finding is unverified (`"status": "unverified"` in CLI JSON, `verification_status: "unverified"` in API responses). Reports omit source snippets and raw Semgrep JSON and identify the target by a hash, but they can still contain relative file paths and rule IDs. Review them before sharing.

## 4. Start the dashboard for one project

Build the dashboard once, then pass the directory to scan:

```sh
(cd frontend && npm ci && npm run build)
uv run --locked python -m ai_code_security_analyzer.api "$SAMPLE"     # or any project directory
uv run --locked python -m ai_code_security_analyzer.api ~/code/my-app --port 8766
```

Before the server starts, the command checks the following, and on any problem prints `error: <code>` with a fix and exits with code 2:

- The directory exists, is a real path with no symbolic link (on macOS `/tmp` is one; use `pwd -P`), and does not overlap the rules directory.
- `frontend/dist` has been built.
- Semgrep runs and supports the options scans need.
- The port is free.

It then prints the dashboard address and an API token created for this run. Open the address and paste the token into **로컬 API 토큰**. Stop the server with Ctrl+C.

- The browser cannot change which directory is scanned. Only the dashboard's own origin is allowed, and the dashboard shows the project as `Local Project`, never its path.
- The generated token is shown only when the output is an interactive terminal; nothing writes it to a file. To use your own token, set `AI_CODE_SECURITY_API_TOKEN`; it is then not printed.
- `AI_CODE_SECURITY_ALLOWED_ORIGINS` adds origins, for example the Vite dev server below. `AI_CODE_SECURITY_RULES_DIR` still selects the rules.
- The bundled rules cover JavaScript/TypeScript and Firestore security rules. A project with no such files, such as a Python-only project, scans as `partial` with no findings. That is not a clean result.

## 5. Advanced: configure with environment variables

Without a project directory, the API reads only environment variables. Use this for several targets (`AI_CODE_SECURITY_TARGETS`) or scripted setups. The browser cannot choose arbitrary paths.

| Variable | Required | Meaning |
| --- | --- | --- |
| `AI_CODE_SECURITY_API_TOKEN` | Yes | 43–256 characters from `[A-Za-z0-9_-]`. Required for `POST /api/v1/scans` and all `/api/v2` calls. `GET /api/v1/health` and `/api/v1/options` do not require it. |
| `AI_CODE_SECURITY_TARGET` | One of these two | A single target directory, exposed as target ID `local-project`. |
| `AI_CODE_SECURITY_TARGETS` | One of these two | JSON array of up to 32 `{"id","label","path"}` objects with absolute paths. Setting both variables is rejected. |
| `AI_CODE_SECURITY_ALLOWED_ORIGINS` | For browser use | Comma-separated exact Origins (no wildcard). Requests carrying any other `Origin` header are rejected. |
| `AI_CODE_SECURITY_RULES_DIR` | No | Trusted rules directory. Defaults to the repository `rules/`. |

Generate a token (43 URL-safe characters):

```sh
uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Use a dedicated value. Do not commit it or paste it into shared logs.

**Option A: built dashboard served by the API (single origin).** When `frontend/dist` exists, the API serves it at `/`.

```sh
(cd frontend && npm ci && npm run build)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:8765' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:8765` and enter the token in the dashboard. The token is kept only in page memory and is lost on reload.

**Option B: Vite dev server.** Vite binds to `127.0.0.1:5173` and proxies only `/api` to `127.0.0.1:8765`.

```sh
# Terminal 1
cd frontend && npm ci && npm run dev
# Terminal 2 (repository root)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:5173`. The one-project command also works here: set `AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173'` and pass the directory.

## 6. Review findings and export results

In the dashboard (UI text is Korean):

1. Choose a registered target and the **Baseline Rules** profile, then run a scan. Experimental profiles are labeled as such.
2. Select a finding to see its rule, location, severity, triage guidance, and which evidence claims were validated or restricted.
3. Set a review status and optional note per finding. This state lives **only in browser memory** (see limitations).
4. Run a second scan of the same target and profile to compare finding IDs. Finding IDs depend on line and column, so a finding whose code moved or whose file was renamed shows up as disappeared plus new. Comparison is blocked when either scan is partial or failed, or when findings were omitted (the API returns at most 50 findings per scan).
5. Export what you need:
   - Current-scan Markdown summary (`Markdown 다운로드`)
   - SARIF 2.1.0 file (`SARIF 다운로드`). No upload is performed.
   - Analyst review Markdown, with notes included only after explicit confirmation
   - Review backup JSON (`검토 기록 백업 JSON 다운로드`), which can be restored onto findings with the same IDs
   - Comparison Markdown for two observed scans

Exports are built from data already in the page and never re-run Semgrep. Downloaded files persist on disk, so check notes before sharing.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `error: <code>` with a `fix:` line | Printed by the one-project command before the server starts (section 4). Follow the fix. Codes: `project_directory_invalid`, `project_path_has_symlink`, `project_overlaps_rules`, `dashboard_build_missing`, `semgrep_not_installed`, `version_check_failed`, `version_check_timed_out`, `semgrep_unsupported`, `port_in_use`, `port_unavailable`, `token_display_unavailable`, `api_token_invalid`, `allowed_origins_invalid`, `rules_directory_invalid`, `target_configured_twice`. |
| API exits with `local_api_configuration_required` | No project directory and no environment configuration. Pass the directory to scan (section 4), or set `AI_CODE_SECURITY_API_TOKEN` and one of `AI_CODE_SECURITY_TARGET` / `AI_CODE_SECURITY_TARGETS`. |
| API exits with `local_api_configuration_invalid` | Token shorter than 43 characters or containing other characters; both target variables set; or malformed `AI_CODE_SECURITY_TARGETS` JSON (relative paths, extra keys, more than 32 entries). |
| API does not start, or a different instance answers | The port (default `127.0.0.1:8765`) is taken. Check with `lsof -nP -iTCP:8765 -sTCP:LISTEN` and stop that instance yourself, or pass `--port`. |
| `403 origin_not_allowed` | The page's exact Origin is missing from `AI_CODE_SECURITY_ALLOWED_ORIGINS` (`http://127.0.0.1:8765` for Option A, `http://127.0.0.1:5173` for Option B). |
| `401 unauthorized` | Missing or wrong token in the dashboard. |
| "Results come from different server runs" or "the server was restarted" | The API was restarted while the page was open. Results from before the restart are kept on screen but cannot be compared with new ones. Save a new baseline and scan again. |
| Scan reports `partial` with `no_files_scanned` (API issue `evidence_unavailable`) | The target has no files the rules apply to (only JavaScript/TypeScript and Firestore rules are covered, so a Python-only project lands here), or its path falls under Semgrep's default ignore patterns (observed for a target inside `tests/`). For the latter, scan a copy in a neutral directory. |
| `semgrep_not_installed` or `version_check_failed` | Semgrep is not on `PATH` or does not run. Install `semgrep==1.182.1` as shown above. |
| CLI exit code 2 with `--output` | The output file already exists, or the format is not `json` / `review-md`. |
| `npm ci` or `node` fails | Use Node.js 24 (`.nvmrc`: 24.22.2). Other major versions are not tested. |
