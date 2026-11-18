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
  - then copies the artifacts into `docs/assets` and prints the source commit, environment and any committed files the run did not regenerate.
- The result is reviewed with `git diff` and committed with the printed provenance.
- CI runs `npm run test:evidence` (a static check plus the capture script's behaviour on a throwaway repository). After the browser stages, it fails if `docs/assets` has changed.

Other options considered:
- Setting Playwright's `outputDir` alone does nothing, because the specs write absolute paths.
- An environment flag that switches the specs to write into `docs/assets` would leave partial captures in place on failure.
- Making the files read-only, or relying on a Git hook, only detects the problem locally.
- Removing evidence capture from the tests would lose coverage of the capture code and the ability to refresh the evidence.

## Limits

- The committed evidence is still stale. Refreshing it is a separate, reviewed decision, ideally made in one fixed environment.
- The 147 tracked files that no current spec produces are historical records of earlier UI phases. The capture step never deletes or changes them.
