[한국어](README.md) | [English]

# SAST Review Workspace

A local workspace for reviewing Semgrep OSS static-analysis results: triage them, record decisions, compare them with a rescan, and export them. Detection is done by Semgrep OSS 1.182.1 with local rules, and every finding is an unverified candidate, not a confirmed vulnerability.

## Features

- Static code analysis with Semgrep OSS (local rules)
- Python CLI and React dashboard
- Review status and notes per finding
- Comparison with a rescan
- Markdown and SARIF 2.1.0 export
- Token-protected, loopback-only FastAPI (`127.0.0.1:8765`)

## Dashboard

![Dashboard scan results](docs/assets/readme/dashboard-results.png)

## Quick start

Requirements: Python 3.12, [uv](https://docs.astral.sh/uv/), Semgrep 1.182.1, and Node.js 24 for the dashboard.

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
uv sync --locked
```

CLI scan:

```sh
SAMPLE="$(cd "$(mktemp -d)" && pwd -P)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

It prints `Status: completed` and `Findings: 7 unverified candidate(s)`.

Dashboard: build it once, then start it with the directory to scan (here, the sample):

```sh
(cd frontend && npm ci && npm run build)
uv run --locked python -m ai_code_security_analyzer.api "$SAMPLE"
```

The command checks the directory, the dashboard build, Semgrep and the port, and prints a fix if one is wrong. It then prints the dashboard address and an API token created for this run. Open `http://127.0.0.1:8765` and paste the token. Use `--port` for another port. The rules cover JavaScript/TypeScript and Firestore security rules; files in other languages are not scanned.

Semgrep runs without OS-level isolation, so scan untrusted repositories only in a separately isolated environment.

## Documentation

- [Getting started](docs/getting-started.md): environment variables, dev server, exports, troubleshooting
- [Project overview](docs/project-overview.md): architecture and security controls
