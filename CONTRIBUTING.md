# Contributing

1. `make setup`, then `make check` must pass before you open a pull request.
2. Behaviour changes need tests that would fail without the change. Do not weaken or skip tests to get green; do not add `|| true` / `continue-on-error` to CI.
3. Keep the core promise: **unknown stays unknown**. Anything that can turn a missing or failed evaluation into "clean", a hypothetical outcome into "verified", or an inferred edge into a declared one will be rejected.
4. Parsers must stay static and bounded (see `docs/threat-model.md`). New formats need fixtures, line-number provenance where cheap, and fuzz coverage in `backend/tests/test_security_osv.py`.
5. Fixtures are synthetic: `demo-*` packages and `DEMO-*` advisories, fake credentials only. Regenerate them with `python scripts/generate_examples.py`.
6. UI changes: keep dark as the default, test both themes, keep keyboard access and accessible names (`tests/e2e/journey.spec.ts` covers the main flows).
7. Commit messages: imperative mood, one logical change each.
