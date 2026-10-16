## What this changes

<!-- What the firewall now allows, asks, holds or denies differently, or what else changes. -->

## Why

## Checks

- [ ] `npm run typecheck && npm run lint && npm test` pass
- [ ] A change in `browser/` or `python/` passes that part's own checks (CONTRIBUTING.md)
- [ ] `npm run check:docs` passes (run `npm run gen:docs` after changing the CLI or rules)
- [ ] `npm run friction` and `npm run mail-friction` still report 0 interruptions / 0 withheld
- [ ] A change to a decision comes with a test, including the refusal case
- [ ] Anything that now blocks more or allows less is in `CHANGELOG.md`
- [ ] No real secrets, tokens or private paths in code, fixtures or this description

<!-- A fix for a security bypass should be coordinated through security@launchsafe.com first (see SECURITY.md). -->
