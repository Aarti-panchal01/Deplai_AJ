# Changelog

This changelog is derived from git log commit subjects in this repository.

## [Unreleased]
### Fixed
- Terraform Agent tests: ported the stale `_execute_run` tests to `run_pipeline`; `test_param_selector.py` and `test_validator.py` are now real pytest tests (the validator integration test skips when `terraform` is not installed).
- Agentic Layer tests: `test_remediation_batching.py` no longer replaces the real `utils` module for the other test files.
- Python: removed `invalid escape sequence` warnings in `terraform_apply.py` and `engine/bundle.py`. This also fixes the generated `perl` map()/EIP rewrite commands, which previously received control characters instead of `\b`, `\1` and `\2`.
- Connector: replaced explicit `any` with typed DB rows (`DbRow`), webhook payload types and `unknown` errors (new `src/lib/errors.ts`). ESLint errors 79 -> 10 (the rest are React Compiler rules in `findings.tsx`, `landing-text-animation.tsx`, `ManageInstancesApp.tsx`).

### Changed
- Settings: removed fabricated demo content that was shown as real account data (a hardcoded profile, fake passkey/MFA, invented login sessions, fake usage and billing numbers) and the tabs that were pure mock-ups (Notifications, Preferences, AI Defaults, user Integrations). Account now shows the real GitHub identity; Security explains that sign-in is GitHub-only; Sessions shows the real current session with a working Sign out; Usage shows live project/installation counts.
- Settings: every remaining button now works. New: `POST /api/settings/test-github` (authenticates as the GitHub App and returns public metadata), `POST /api/settings/validate-aws` backed by `POST /api/aws/validate-credentials` in the Agentic Layer (STS GetCallerIdentity), and `GET /api/settings/export` (JSON download of your own data; secrets and server paths excluded).
- The GitHub App install link is configurable via `NEXT_PUBLIC_GITHUB_APP_SLUG`.

### Added
- Semgrep as a second SAST engine next to Bearer (see `SEMGREP_*` in `.env.template`).
- Bandit as a third SAST engine (official image, offline, `BANDIT_*` settings) and a cross-engine merge (`code_findings.py`): findings are clustered by weakness family and overlapping line range, so one bug reported by several engines is one finding with an `engines` list (shown as a badge in the Security Analysis page). Severity is resolved by consensus; weak-PRNG without security context is demoted, hardcoded credentials are at least medium, findings in test code are one level lower, audit-style Bandit checks (B108, B310) and empty/placeholder "passwords" are not reported as medium findings, and one canonical CWE is shown for families where engines' CWE metadata is wrong (e.g. Semgrep tags SQL injection as CWE-704). On the benchmark app, detection rose from 7 to 9 of 25 findings (+3 partial) and duplicate rows fell from 3 to 0.
- `npm test` in the Connector (Node's built-in test runner) with tests for the export helper and error helpers.

### Added (CI)
- GitHub Actions CI (`.github/workflows/ci.yml`), Dependabot and a pull request template. Lint and dependency-vulnerability ratchets (`Connector/.eslint-baseline.json`, `.trivy-baseline.json`).

### Fixed
- The LLM remediation agent (`Analysis/dataingestor.py`) read only Bearer and Grype, so Semgrep and Bandit findings never reached it; it now uses the same merged findings as the dashboard.

### Fixed (CI findings)
- `next build` failed on a clean checkout because Turbopack cannot bundle `ssh2`'s native binding (EC2 logs route); `ssh2` is now a `serverExternalPackages` entry. The production Docker image build failed for the same reason.
- `.gitignore` blanket `*.json` / `*.mjs` rules silently excluded new config files; added exceptions for the CI files.

### Removed
- Orphaned `neo4j` and `qdrant` services, volumes and settings from the production compose file, `deploy/.env.example` and `deploy/README.md` (the KG agent was removed on 2026-07-20).
- One-off root scripts (`fix.py`, `fix_react_icons.py`, `patch_agents.py`, `patch_main*.py`) and scratch files (`test_index.html`, `tmp_stages_ui.tsx`).

## [0.2.0] - 2026-04-08 to 2026-07-20
### Added
- BYOK: user-supplied LLM configuration wired into the implementation pipeline.
- EC2 components, granular provisioning report for resource status.
- Landing page v0.1/v0.2.
- Production Docker deployment with Caddy TLS (`docker-compose.production.yml`, `deploy/`).

### Changed
- Upgrade packs v2.0 and later; cost estimator, pipeline clone and deployment UI gating fixes.
- Fixed mixed-bundle deployments and a Suspense/Turbopack build error.
- Production startup fixes for scan and Terraform services.

### Removed
- Unused graph services and the KG agent.

## [0.1.1] - 2026-04-05
### Changed
- settings-ui (8fbd30024d41cc1e1cafc9658dae8d75840c2b70)

### Fixed
- bug fixes (629de7fc0986732f4a8cc769a4658403050475f2)

## [0.1.0] - 2026-04-03
### Released
- /release 0.1.0 (1ee5f94b3ea6b867e2f18d294117d8e4110cb2a0)

## [0.0.x] - 2026-03-21 to 2026-04-02
### Changed
- bug fixes (201a2da8f88774e0dce7b4be7cd54d76663b519f)
- upgrade pack v0.4 (1286181425b19acad5a45d02f8fa299a97571da2)
- fix: include agentic runtime and terraform execution updates (a0c595ca003edbbfc31d888dddd5526d86b598a6)
- upgrade v3.5 (3b9b7fe7f215db44c060bc66f98b34da96b320f6)
- update readme (8a2daa9b37cf490930981eb538aea06f9ce8ce4a)
- upgrade v0.31 (92af3dff540308ee9c7d1d0acada7a68bdecb393)
- upgrade pack_v0.3 (516378f1bf84850da34781e6650cff944dfc7f9d)
- bug fixes (526e5bb505f6e0c9b903a6091810a88b3c197f6c)
- upgrade pack (79f085d6bf28f8b20c92f1ed11c9ddb9c922af6a)
- bug fix (7fbda0cd09521c66eda41423dc8a8e025554eb2d)
- upgrade_v0.2 (297a8fef49ff5a0b31f63d1cabe182877ff1c0e7)
- bug fixes (be8b37110646ec7d2c6bcded37ea0df3063141af)
- upgrade pack (82bab2030bc872b0c27259c1730a56821f2551d2)
- upgrade pack (734af62e95ddd18871955baad833e26bba861a26)
- remove useless files (9a10c1e59ca38d524edece89c23347ab7262f2d1)
- updates (a02c2ab2a096eb9eb61a5666949f7a6b8498f0ee)
- chore: reset history to current project snapshot (2b410ec615bbb2c1b783d1fdd508741d0178a5e2)

## Notes
- Several commit messages are generic (for example bug fixes and upgrade pack), so detailed change intent is not available from commit metadata alone.
