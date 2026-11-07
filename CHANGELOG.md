# Changelog

## 0.1.0

First release.

- `pwnstop guard`, before every shell command: blocks piping the internet into a shell, reading credentials, sending secrets out, wiping `/` or `~`, SSH and cron backdoors, turning off protections, `chmod 777`, untrusted package indexes, and installing or running packages that are missing, pulled for malware, under 30 days old or known vulnerable (OSV).
- `pwnstop verify`, before the agent says done: scans the lines added in the session for 18 kinds of holes, `.env` files git would commit, and new dependencies in `package.json`, `requirements*.txt` and `pyproject.toml`. Each finding blocks once.
- `pwnstop check [--base REF]` for CI and git hooks; `pwnstop: ignore` on a line for reviewed exceptions.
- `pwnstop init [--global]` for Claude Code, Codex CLI, Cursor, Gemini CLI and GitHub Copilot CLI.
