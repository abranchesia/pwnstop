<!-- What this changes, and why. -->

- [ ] `uvx pytest -q` passes.
- [ ] A new or changed rule has a case it flags and a safe look-alike in `tests/test_pwnstop.py`, and was run on the history of a real repo: `pwnstop check --base $(git rev-list --max-parents=0 HEAD | tail -1)`.
- [ ] `CHANGELOG.md` has a line under `[Unreleased]` if users will notice the change.
