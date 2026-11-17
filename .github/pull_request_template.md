## What and why
<!-- One or two sentences: what changes, and the problem it solves. -->

## How it was tested
<!-- Commands run, screenshots, or "not tested" with the reason. -->

## Checklist
- [ ] CI is green (types, lint ratchet, tests, build)
- [ ] New behaviour has tests; bug fixes have a regression test
- [ ] No secrets, tokens or customer data in the diff
- [ ] Docs, `CHANGELOG.md` and `.env.template` updated if behaviour or configuration changed
- [ ] Database changes are backward compatible with the previous release (expand, then contract)
- [ ] Lint did not get worse (if it improved: `npm run lint:ratchet -- --update`)
- [ ] No "coming soon" UI added for features that do not exist yet

## Risk and rollback
<!-- What could break? How do we roll back? -->
