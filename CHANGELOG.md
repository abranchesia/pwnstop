# Changelog

## 0.1.0

First release.

- `pwnstop guard`, before every shell command: blocks piping the internet into a shell, reading credentials, sending secrets out, wiping `/` or `~`, SSH and cron backdoors, turning off protections, `chmod 777`, untrusted package indexes, and installing or running packages that are missing, pulled for malware, under 30 days old or known vulnerable (OSV).
- `pwnstop verify`, before the agent says done: scans the lines added in the session for 21 kinds of holes, `.env` files git would commit, and new dependencies in `package.json`, `requirements*.txt` and `pyproject.toml`. Each finding blocks once.
- `pwnstop check [--base REF]` for CI and git hooks, with findings shown on the PR's lines in GitHub Actions; `pwnstop: ignore` on a line for reviewed exceptions.
- `pwnstop check FOLDER` audits every line of the skills, rules and plugins you installed.
- Agent files (skills, `AGENTS.md`, `CLAUDE.md`, rules, hooks, MCP configs) get the guard's command rules; any file gets `hidden-text` (Unicode tags, bidi controls, zero-width runs); code gets `secret-default`; workflows get `pwn-request`.
- MCP servers are package-checked, both from `claude`/`codex`/`gemini mcp add` and from `.mcp.json`/`mcp.json`.
- The guard blocks base64 or hex decoded into a shell (`obfuscated-command`) and lets `curl … | python3 -m json.tool` run.
- `pwnstop init [--global]` for Claude Code, Codex CLI, Cursor, Gemini CLI and GitHub Copilot CLI.
