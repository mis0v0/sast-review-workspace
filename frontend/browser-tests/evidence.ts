import { mkdirSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Browser tests record screenshots and layout measurements while they run.
 * They always write below Playwright's ignored output directory, which
 * Playwright empties at the start of every run, never into the committed
 * `docs/assets` tree. Paths mirror `docs/assets`, so
 * `scripts/capture-browser-evidence.mjs` can promote a complete, successful
 * run there as an explicit, reviewable step.
 *
 * The root is anchored to this file, not to `process.cwd()`, so the launch
 * directory cannot redirect where evidence lands.
 */
export const evidenceRoot = fileURLToPath(new URL('../test-results/evidence/', import.meta.url));

export function evidencePath(relativePath: string): string {
  const path = resolve(evidenceRoot, relativePath);
  const inside = relative(evidenceRoot, path);
  if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
    throw new Error(`evidence_path_outside_root: ${relativePath}`);
  }
  mkdirSync(dirname(path), { recursive: true });
  return path;
}
