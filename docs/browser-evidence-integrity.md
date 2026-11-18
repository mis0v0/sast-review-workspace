# Browser evidence integrity

## Problem

Browser specs wrote screenshots and layout measurements straight into `docs/assets/`, using paths built from `process.cwd()`. Any routine `npm run test:browser` rewrote 135 committed files (136 with the real E2E run), and a run from another directory wrote somewhere else. A failed or partial run left a mix of new and old files in place, which is easy to commit by accident.

## Drift analysis (2026-11-18, macOS arm64, Chromium 156)

- **Stale evidence (primary, established).** Every evidence directory was last committed between 2026-10-31 and 2026-11-03. The UI changed after that, including a full theme replacement (`f4d4c21`, 2026-11-12). In `computed-style-samples.json`, 977 of 1,262 shared values differ, including colours, font sizes, line heights and selectors, which font rendering cannot change.
- **Environment-dependent fonts (contributing, not isolated).** The font stack starts with `Inter`, which the project does not bundle. Without it, macOS falls back to the system font and Linux to `Noto Sans KR` or `sans-serif`, so text geometry depends on the machine. The original capture machine is unknown, so its share of the drift cannot be measured.
- **Nondeterminism (minor).** On one machine, all five JSON files and most screenshots were byte-identical across two runs. `regression-captures/completed-1440x900.png` was not.
- **Stale build input.** `test:browser` serves the existing `dist/` and does not rebuild it.

## Design

- Specs get evidence paths only from `browser-tests/evidence.ts`. It anchors them to `frontend/test-results/evidence/` (ignored by Git), mirrors the `docs/assets` layout and rejects paths that escape that folder.
- `npm run evidence:capture` (or `evidence:capture:real` with `SEMGREP_REQUIRED=1`) rebuilds the dashboard and runs `scripts/capture-browser-evidence.mjs`. That script:
  - refuses to start if `docs/assets` has any uncommitted change;
  - clears the staging folder and runs the test command with `CI=1`;
  - fails if the run wrote into `docs/assets` directly;
  - promotes nothing unless the command succeeded and every artifact is a non-empty regular `.png` or `.json` file that parses;
  - then publishes the artifacts into `docs/assets` and prints the source commit, environment and any committed files the run did not regenerate.
- The result is reviewed with `git diff` and committed.
- CI runs `npm run test:evidence` (a static check plus the capture script's behaviour on a throwaway repository). After the browser stages, it fails if `docs/assets` has changed.

### Publication integrity (added 2026-11-18)

Two defects were reproduced in the first version of the script:
- **Partial publication.** A failure while copying left some files replaced and others not. With one target file unwritable, `a/1.png` was replaced, `b/2.png` was not, and the script exited with a raw `EACCES` trace. A full disk could also leave a truncated file.
- **Concurrent captures.** A second capture started during the first wiped its staging folder. The first then exited 0 and published only the files written after the wipe.

The script now:
- holds a lock in the working tree's Git directory (exit code 3 if one is held);
- writes every file next to its target and checks its hash before changing anything;
- swaps the files in, keeping each old file as a backup, and restores the backups on any error;
- treats SIGINT and SIGTERM as "publish nothing";
- writes `docs/assets/browser-evidence-manifest.json` in the same transaction. For each published file, the manifest records its SHA-256, capture time, source commit, whether tracked files were modified, OS, Node, Playwright and Chromium versions, and the command. Entries for files a capture did not regenerate are kept unchanged.

CI checks that every manifest entry still matches its file, so editing or replacing a published file afterwards is detected.

What the tests show and what they don't:
- **Shown:**
  - Failures while writing (permission denied, and `ENOSPC` on a real 6 MB volume) leave `docs/assets` byte-identical, with no temporary files left behind.
  - A failure while swapping (a macOS immutable file) restores every previous file.
  - The lock blocks a second capture, and an interrupted capture publishes nothing.
- **Not atomic:** a hard kill or power loss during the swap. The leftover `*.evidence-*` files are untracked, so the next capture refuses to start, and Git still holds the previous evidence.

## Reproducibility

Measured on one machine (macOS arm64, Chromium 156.0.8078.4), with two complete runs from the same build:
- All 5 JSON measurement files were byte-identical.
- 55 of 130 screenshots differed, all with unchanged image sizes, in three groups:
  - **Wall-clock content.** The dashboard shows `결과 수신: <time>`, and the text is formatted with the host's timezone and locale, so it differs on every capture by design.
  - **Rendering noise.** Pixel deltas of 4–22 in otherwise identical frames.
  - **A few unexplained regional changes**, up to 6% of pixels, for example in `phase8g/webkit-mobile-drawer-390.png`, which is captured without `animations: 'disabled'`.

So, for this project:
- **Reproducible evidence** means JSON measurements that are identical when captured in the same recorded environment.
- **Screenshots** are illustrations of a recorded environment and time. They are checked by eye and by the browser tests' assertions, never by comparing bytes.
- **Evidence from different environments** may only be compared with its environment in view. The manifest makes this possible.

Rejected for now:
- A fixed clock or timezone in all browser tests: the app's expiry logic reads `Date.now`, and it would change the behaviour of 88 tests.
- Bundling the `Inter` font: a product change that still would not make rendering identical across operating systems.
- A container: a reasonable next step for a single canonical capture environment, but not needed to make publication safe.

Other options considered:
- Setting Playwright's `outputDir` alone does nothing, because the specs write absolute paths.
- An environment flag that switches the specs to write into `docs/assets` would leave partial captures in place on failure.
- Making the files read-only, or relying on a Git hook, only detects the problem locally.
- Removing evidence capture from the tests would lose coverage of the capture code and the ability to refresh the evidence.

## Limits

- The committed evidence is still stale and has no manifest entries, so its provenance is unknown. Refreshing it is a separate, reviewed decision, ideally made in one fixed environment.
- The script cannot know which artifacts a run should have produced. A test that skips its capture leaves the older file in place, which is reported as "not regenerated" only within the folders the run touched.
- The 147 tracked files that no current spec produces are historical records of earlier UI phases. The capture step never deletes or changes them.
