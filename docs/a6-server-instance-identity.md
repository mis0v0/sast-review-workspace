# A6 — Server instance identity

A scan result carried nothing that identified where it came from. The dashboard labelled each result with the target it had asked for, using options it fetched once. After the server was restarted on another folder, a tab kept open with the same token and port compared the old baseline with the new project's results as if they were one project. Two different projects can even produce byte-identical scan responses, because finding IDs hash only the rule and the position.

This change makes the dashboard compare only results produced by one running server process. It does not identify projects.

## Contract

- Every HTTP response, including errors, boundary denials, preflights and the dashboard files, carries `X-Server-Instance`: 22 random URL-safe characters, created when the app is created. It is not secret, not derived from any path or file metadata, never stored, and different after every restart. Inner layers cannot set or remove it.
- The CORS policy exposes the header to the configured origins. Boundary denials (`401`, `403`, `415`, `413`) still carry no CORS grant, as before.
- Response bodies are unchanged. No new field appears in `/health`, `/options`, `ScanResponse` or the investigation API.

## Dashboard behaviour

- Each result records the instance only when it matches the instance that served the options the request was built from. Otherwise the instance is unknown.
- Two results are comparable only if both instances are known and equal (`server_instance_unavailable`, `server_instance_mismatch`). Investigation runs follow the same rule.
- A scan answered by another instance is discarded: the shown result and its review records stay, evidence handles from the old process are forgotten without contacting the new one, the options are reloaded, and the user is told to scan again. Handles issued by the new process for the discarded answer are released.
- A request in flight when the server stops fails with a connection error and leaves no result or evidence.
- The instance never appears in Markdown, SARIF or backup exports.
- Review backups stay portable. The restore preview now says that it does not check whether the backup came from the current project, and lists what it does compare.

## Not covered

- Results from two runs of the same project cannot be compared. The server cannot prove they are the same project; save a new baseline after a restart.
- A backup still fits a different project whose findings sit at the same rule and positions.
- Within one server run, a folder whose contents are replaced while keeping its directory identity looks like an edited project.
- More than one server worker per process would break the rule; the server runs one worker.
- Enforcement is in the browser, where baselines live. Server-side investigation evidence was already bound to one process.

## Verification

- `tests/test_server_instance_identity.py`: header on every kind of response, uniqueness per app instance, no project data, CORS exposure, forging refused, identical bodies from two projects.
- `frontend/tests/server-instance.test.tsx`: header parsing, comparison and investigation rules, exports, restart handling in the dashboard, backup wording.
- `frontend/browser-tests/real-server-restart.spec.ts`: real Chromium, FastAPI and Semgrep, restarted on the same port with the same token; a scan in flight during a restart; header readable from another allowed origin and not from others.
