#!/usr/bin/env node
/**
 * Lint ratchet: CI fails if ESLint reports MORE errors or warnings than the committed baseline.
 * The baseline only ever goes down: when you fix lint problems, run
 *   npm run lint:ratchet -- --update
 * and commit the new .eslint-baseline.json.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const baselinePath = join(root, '.eslint-baseline.json');
const update = process.argv.includes('--update');

const run = spawnSync('npx', ['eslint', '.', '--format', 'json'], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 256 * 1024 * 1024,
  shell: process.platform === 'win32',
});

let results;
try {
  results = JSON.parse(run.stdout);
} catch {
  console.error('Could not parse ESLint output.\n' + (run.stderr || run.stdout).slice(0, 2000));
  process.exit(2);
}

const current = results.reduce(
  (total, file) => ({
    errors: total.errors + file.errorCount,
    warnings: total.warnings + file.warningCount,
  }),
  { errors: 0, warnings: 0 }
);

if (update) {
  writeFileSync(baselinePath, JSON.stringify(current, null, 2) + '\n');
  console.log(`Baseline updated: ${current.errors} errors, ${current.warnings} warnings.`);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
console.log(`ESLint: ${current.errors} errors / ${current.warnings} warnings (baseline ${baseline.errors} / ${baseline.warnings})`);

if (current.errors > baseline.errors || current.warnings > baseline.warnings) {
  console.error('Lint got worse than the baseline. Fix the new problems (run `npx eslint .` to see them).');
  const worst = results
    .filter((file) => file.errorCount + file.warningCount > 0)
    .sort((a, b) => b.errorCount - a.errorCount || b.warningCount - a.warningCount)
    .slice(0, 5);
  for (const file of worst) {
    console.error(`  ${file.filePath.replace(root + '/', '')}: ${file.errorCount} errors, ${file.warningCount} warnings`);
  }
  process.exit(1);
}

if (current.errors < baseline.errors || current.warnings < baseline.warnings) {
  console.log('Lint improved. Lock it in with: npm run lint:ratchet -- --update');
}
