# Contributing

Thanks for helping. pwnstop is small on purpose: one file (`pwnstop.py`), Python 3.9+, standard library only. Changes that keep it that way are the easiest to merge.

## Set up

```bash
git clone https://github.com/abranchesia/pwnstop && cd pwnstop
uvx pytest -q                       # the tests, no other setup
python3 pwnstop.py --help           # run it from the checkout
python3 pwnstop.py check some/dir   # scan every line in a folder
```

The tests never touch the network: they fake the registries and OSV.

## What helps most

- **Reports from agents marked 🧪** (Codex CLI, Cursor, Gemini CLI, Copilot CLI). [Open an issue](https://github.com/abranchesia/pwnstop/issues) and say whether the guard blocked a command and whether the stop check sent the agent back, with your `pwnstop --version`.
- **False alarms.** Paste the line and the rule. A rule that cries wolf gets ignored, so these get fixed first.
- **New rules.** A shell command goes in `COMMANDS`, a line of code in `RULES`. Add a case that is flagged and one that looks close but is safe to `tests/test_pwnstop.py`. Then measure the false alarms on the whole history of two or three real repos before opening the PR:

  ```bash
  cd some/real/repo
  python3 path/to/pwnstop.py check --base $(git rev-list --max-parents=0 HEAD | tail -1)
  ```

- **Agent adapters.** A new agent needs an entry in `HOOKS` and `BINARIES`, its payload told apart in `agent_of()`, and its way to refuse a command and to keep working in `deny()` and `reply()`.

## Rules of thumb

- It never bricks the agent. No git, no network, a timeout or a bug in pwnstop skips the check: it never blocks for something the agent can't fix.
- Only the names of packages being added leave the machine, to the registries and OSV. No telemetry.
- The stop check only looks at lines added in the session, so old code never blocks anyone. Each finding blocks once.
- The message tells the agent what to do instead, with the code or command to use.
- Code reads like the code around it: short functions, a docstring when the "why" isn't obvious.

## Releasing

1. Move the `[Unreleased]` notes in `CHANGELOG.md` under the new version, with the date.
2. Bump `version` in `pyproject.toml` and commit (`pwnstop X.Y.Z`).
3. Run `git tag vX.Y.Z && git push origin vX.Y.Z`. The release workflow runs the tests and publishes to PyPI through Trusted Publishing, with no token stored.
4. Run `gh release create vX.Y.Z --title "pwnstop X.Y.Z"` with the changelog section as the notes.

PyPI never takes the same version twice, even after a delete: a fix after a release is a new version.
