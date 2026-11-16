# Local project onboarding (A7)

`python -m ai_code_security_analyzer.api PROJECT_DIR` starts the dashboard for one local directory. Before A7, a new user had to:

1. generate a token;
2. set three environment variables: target, token and allowed origin;
3. know the exact origin format;
4. start a launcher fixed to port 8765.

A missing dashboard build or a missing Semgrep surfaced only later, as a blank page or a failed scan.

## What the command does

| Step | Before | Now |
| --- | --- | --- |
| Choose the project | `AI_CODE_SECURITY_TARGET=<abs path>` | Positional argument; relative paths resolve against the current directory |
| API token | Generate one and export it | Generated per run and shown only on an interactive terminal; `AI_CODE_SECURITY_API_TOKEN` still overrides it and is then not printed |
| Allowed origin | `AI_CODE_SECURITY_ALLOWED_ORIGINS=http://127.0.0.1:8765` | The dashboard's own origin; the variable only adds origins |
| Port | Fixed 8765 | 8765 by default, or `--port` |
| Prerequisites | Found when a scan fails | Checked before start: directory, dashboard build, Semgrep, port; each failure prints `error: <code>` and a fix, then exits with code 2 |

Without `PROJECT_DIR`, the launcher behaves as before, reading only environment variables. The one exception is that `local_api_configuration_required` now also suggests passing a directory.

Installation is a separate step and unchanged: Python 3.12, uv, Semgrep 1.182.1, Node.js 24, `uv sync --locked`, and a one-time `(cd frontend && npm ci && npm run build)`. This is not a one-command installation.

## Security boundary

- **Unchanged guarantees.** The server still binds only `127.0.0.1` with one worker. Host, Origin and token checks, path validation and target binding are unchanged (`ApiSettings`), and so are the A4 Git isolation, the A5 link handling and the A6 instance header. The launcher builds the same `ApiSettings` and `create_app` as the environment path.
- **What the browser can do.** It still cannot choose or change a path. No endpoint was added, and the options response shows the fixed label `Local Project`.
- **Where the generated token goes.** It is printed only when stdout is a TTY. Otherwise the launch is refused with `token_display_unavailable`, so a redirected log never receives it. The token is never placed in a URL, process arguments, the environment, a file or browser storage; the dashboard still keeps it in page memory only. A test checks `ps eww` for the running process.
- **Rejected token delivery.** Serving the token to the page over HTTP was rejected. Any local process, including other OS users' processes, could then fetch it, which removes the protection the token gives against them.
- **Port check.** The port is checked by connecting first, then binding. A listener on all interfaces would otherwise share the port on macOS.
- **Semgrep check.** The probe runs `semgrep --version` and `semgrep scan --help` in an empty private directory with the scan's isolated environment, never in the target.

## Alternatives considered

- **Native folder picker or HTTP project registration.** Both need a path-accepting endpoint or a platform GUI. A terminal argument already reaches the server with the user's own authority and no new attack surface.
- **Token in a URL fragment, opening the browser automatically, or copying to the clipboard.** These leave the token in browser history, depend on the platform, or expose it to other applications.
- **A separate launcher application or console script.** This adds packaging for no gain over `python -m`.
- **Building the dashboard on first start.** This mixes installation with launching and needs network access.

## Verification

- `tests/test_local_launcher.py` (real subprocesses). It covers the configuration and every refusal: missing path, a file instead of a directory, an empty path, a link in the path or one of its parents, overlap with the rules directory, a missing build, Semgrep missing, broken, unsupported or hanging, an occupied port on loopback or on all interfaces, non-TTY output, and conflicting variables. A run under a pseudo-terminal checks that the printed token is the only one accepted and that it is absent from `ps eww`. It also checks the boundaries (401, 403, the dashboard origin only, no path in options).
- The same file also has a real-Semgrep journey: a Node.js project at a path with spaces and Unicode, then a Python project after a restart on the same port. The A4 canary is not triggered, an outside link is not followed, `node_modules` is excluded, and the instance header changes.
- `frontend/browser-tests/real-launcher.spec.ts` runs the same journey through the real dashboard. It covers review state, restart detection and the partial Python result.

## Limitations

- The token must still be pasted once per launch. Terminal scrollback can retain it.
- Rule coverage is JavaScript/TypeScript and Firestore rules only. A Python-only project is `partial` with no findings.
- One project per launch. Several targets still need `AI_CODE_SECURITY_TARGETS`.
- Tested on macOS (arm64) and Ubuntu 24.04 (arm64 container). Windows is not tested.
