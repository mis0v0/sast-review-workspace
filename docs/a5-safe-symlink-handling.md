# A5 — Safe symbolic-link handling

Before this change the API refused to scan any folder that contained a symbolic link. Ordinary Node.js and Python projects have them (`node_modules/.bin/*`, `.venv/bin/python`), so they could not be scanned at all. This record states what was measured, the policy adopted, and what it does not cover.

## Measured behaviour

Semgrep 1.182.1 with the adapter's exact options, on macOS (arm64) and on Ubuntu 24.04 (arm64 container). Both gave the same result for every case.

| Link in the target | Semgrep | API before | API now |
| --- | --- | --- | --- |
| `node_modules/.bin/*`, workspace links inside `node_modules` | not followed; folder excluded by the adapter | `400` | `completed` |
| `.venv/bin/python` | not followed; folder excluded by the adapter | `400` | `completed` |
| `node_modules` or `.venv` that is itself a link | excluded by name, not followed | `400` | `completed` |
| link to a file or folder inside the target | not followed; the real file is scanned once | `400` | `completed` |
| link to a file or folder outside the target | not followed; nothing outside is scanned | `400` | `completed` |
| dangling link, cyclic links | ignored | `400` | `completed` |
| linked `.gitignore` | not read | `400` | `completed` |
| linked `.git` pointing at a repository with a command in its configuration | excluded; the command does not run | `400` | `completed` |
| linked `.semgrepignore` | **followed**: rules from the linked file are applied | `400` | `400` |
| target root is a link, or a parent folder is a link | Semgrep refuses a linked root | refused at start | refused at start |

## Policy

1. **Root and parents:** unchanged. A linked root or parent is refused when the server starts, and the root's device and inode are rechecked before every scan.
2. **Links below the root are allowed and never followed.** The pre-scan check no longer rejects them. Semgrep does not follow them (table above).
3. **A `.semgrepignore` must be a regular file wherever Semgrep reads one.** A link, FIFO or folder with that name is refused before Semgrep starts, because it is the one link Semgrep reads through. Measured: Semgrep opens ignore files at any depth, including inside `node_modules` and `.venv` although it does not scan those folders, and not inside `.git`. A blocking file there stalls the scan until the time limit. Ignore-file discovery does not follow folder links, and rules nested in a dependency folder cannot hide files outside it.
4. **Dependency folders do not count toward the 100,000-entry limit.** The pre-scan check still walks `node_modules` and `.venv` to apply rule 3, within the same 5-second budget, but their entries are not scanned and are not counted. `.git` is not walked. The Firestore source snapshot skips all three. A large dependency tree therefore no longer rejects the project; the limit still applies to everything that is scanned.
5. **A reported path that passes through a link is refused.** If a finding's path has a link in any component, the finding is dropped and the scan is `partial`. Before, a path through an internal link was silently rewritten to the link's destination. The same rule applies to taint-trace locations.

Rejected alternative: allow links only inside dependency folders. It would still refuse projects with an ordinary link such as `docs/latest -> v2` or a build-tool link to an external folder, and Semgrep's measured behaviour does not need it.

`.gitignore` and `.git` links are not refused. The measurements show Semgrep does not read them under the A4 options, and a regular `.git` folder with the same content is accepted anyway. Tests pin this behaviour, so a Semgrep that starts reading them fails the suite.

## Scan evidence

- A link that is not followed leaves no file inside the root unscanned: the real file is scanned under its own path, and a destination outside the root was never in scope. The scan status is therefore not changed by links.
- When the pre-scan check sees a link outside the excluded folders, the scope evidence carries `symbolic_links_not_followed`. It is an internal limitation code, accepted by the closed registry and evaluator lists. The public `ScanResponse` and investigation responses are unchanged.
- Links never appear in the scanned list. Nothing is added to the skipped list that Semgrep did not report. A skipped entry named `.git`, `node_modules` or `.venv` may itself be a link and is recorded as the adapter's exclusion; nothing below a link is recorded.
- Scope completeness stays `UNVERIFIED`. A `completed` scan does not prove every source file was analysed.
- Investigation: scans of a project with links are `completed` and `COMPARABLE`. A finding whose file was replaced by a link is reported as `PATH_NOT_REPORTED`, `UNDETERMINED`, never as explained.

## Races

The checks narrow the window; they do not close it.

| Change during a scan | Result |
| --- | --- |
| File replaced by a link after the pre-scan check, before Semgrep starts | Semgrep does not follow it; nothing from the destination is reported (tested, deterministic) |
| File with a finding replaced by a link after Semgrep ends, before the output is read | finding dropped, scan `partial`, scanned list withheld (tested, deterministic) |
| `.semgrepignore` replaced by a link or a blocking file after the pre-scan check | not prevented; Semgrep would read the linked rules, which can only narrow the scan (reported as an ignore-file skip in the investigation run), or stall until `timed_out` |
| A link swapped in and back while Semgrep is reading a file | not tested; relies on Semgrep not following links |

Evidence readers already open files component by component with `O_NOFOLLOW` and refuse hard-linked files.

## Not covered

- Semgrep has no OS-level isolation. Scan untrusted repositories only inside a separately isolated environment.
- The adapter does not enforce Semgrep 1.182.1. Link behaviour was measured on that version only; the dropped-finding rule is the fallback if another version follows links.
- A hard link to a file outside the target is scanned as a normal file.
- `:include` inside a regular `.semgrepignore` still reads a file outside the target (see [A4](a4-untrusted-scan-git-hardening.md)).
- Refusals still return the generic `400 target_not_allowed`.
- A real project is often still `partial` in the investigation run for reasons unrelated to links: Semgrep's default ignore list skips `tests/` and `dist/`, and it skips files over its size limit with a reason outside the closed set. Measured on a real checkout with a linked `node_modules` and a `.venv`: refused before this change; now the normal scan is `completed` and the investigation scan is `partial`.
- x86_64 Linux was not tested.

## Verification

`tests/test_symlink_handling.py` covers the table above with the real Semgrep subprocess and the real HTTP API, the pre-scan rules with a stub adapter, the dropped-finding rule with crafted output, both deterministic replacement cases, and the measured ignore-file behaviour that rule 3 relies on.
