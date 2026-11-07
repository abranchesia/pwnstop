# Changelog

## [Unreleased]

### Changed

- README examples use `.example` addresses, which never resolve, instead of domains someone owns.
- README: PyPI badge, and how to contribute and release. New `CONTRIBUTING.md`.

## [0.1.0] - 2026-11-07

First release.

### Added

- `pwnstop guard`, before every shell command: blocks piping the internet into a shell, base64 or hex decoded into a shell, reading credentials, sending secrets out, wiping `/` or `~`, SSH and cron backdoors, turning off protections, `chmod 777`, untrusted package indexes, and installing or running packages and MCP servers that are missing, pulled for malware, under 30 days old or known vulnerable (OSV). `curl … | python3 -m json.tool` runs.
- `pwnstop verify`, before the agent says done: scans the lines added in the session for 21 kinds of holes, including secrets with a default value, invisible text and pwn requests, `.env` files git would commit, and new dependencies in `package.json`, `requirements*.txt` and `pyproject.toml` and MCP servers in `.mcp.json`/`mcp.json`. Agent files (skills, `AGENTS.md`, `CLAUDE.md`, rules, hooks, MCP configs) get the guard's command rules. Each finding blocks once.
- `pwnstop check [--base REF]` for CI and git hooks, with findings shown on the PR's lines in GitHub Actions; `pwnstop: ignore` on a line for reviewed exceptions.
- `pwnstop check FOLDER` audits every line of the skills, rules and plugins you installed.
- `pwnstop init [--global]` for Claude Code, Codex CLI, Cursor, Gemini CLI and GitHub Copilot CLI.

[Unreleased]: https://github.com/abranchesia/pwnstop/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/abranchesia/pwnstop/releases/tag/v0.1.0
