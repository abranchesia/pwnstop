#!/usr/bin/env python3
"""pwnstop: your coding agent can't open the hole an attacker walks through.

Usage:
  pwnstop check [--base REF] [files]
                           scan the git changes (or everything changed since the branch left REF); exit 1
                           on findings
  pwnstop --version        the installed version
  pwnstop start            hook, session start: mark the time and a git snapshot
  pwnstop verify           hook, agent stop: scan the lines added since the mark; findings go back to the
                           agent, each one once

Agents: claude, codex, cursor, gemini, copilot.
A line holding `pwnstop: ignore` is left alone by `check`; one the agent adds in a session is flagged.
No git: the scan is skipped. pwnstop never bricks your agent.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

STATE = Path(tempfile.gettempdir()) / "pwnstop"
IGNORE = "pwnstop: ignore"
SKIP_DIRS = {"node_modules", "dist", "build", "target", "coverage", "out", "vendor", "__pycache__", "venv", ".venv"}
TEST_NAME = re.compile(r"^test_|_test\.|_spec\.|\.(test|spec)\.|Tests?\.\w+$")
TEST_DIRS = {"test", "tests", "spec", "__tests__", "e2e", "Tests", "fixtures"}
DOCS = re.compile(r"\.(?:md|mdx|rst|txt|adoc)$")
LOCKS = re.compile(r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|go\.sum)$|\.min\.js$")
ENV_FILE = re.compile(r"(?:^|/)\.env(?:\.(?!.*(?:example|sample|template|dist|defaults?)$)[\w.-]+)?$")
ENV_FIX = "git would commit it with your secrets: add it to .gitignore and commit only a .env.example without values"

PY, JS = r"\.py$", r"\.(?:[cm]?[jt]sx?|vue|svelte|astro)$"
PYJS = r"\.(?:py|[cm]?[jt]sx?|vue|svelte|astro)$"
CODE = r"\.(?:py|[cm]?[jt]sx?|vue|svelte|astro|go|rb|php|java|kt|cs|rs)$"
INPUT = r"\b(?:request|req)\.(?:args|params|query|body|form|values|GET|POST|files|json|data|query_params|path_params)\b"
SQL = r"(?:select\b[^\"'`]*?\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b"
VALUE = r"(?:[=<>]|\blike|\bvalues\s*\()\s*'?%?"  # where SQL takes a value: = x, > x, LIKE '%x, VALUES (x
JOIN = r"\s*(?:\+\s*\w|%\s*[\w(]|\.format\()"  # a string glued to a value: + x, % x, .format(
# Text a visitor controls, in the browser: the URL, form fields, cookies, messages from other windows.
USER_TEXT = r"(?:\blocation\.(?:hash|search|href)|URLSearchParams|searchParams|\.value\b|\bdocument\.cookie|\b(?:e|ev|event|msg)\.data\b|\.responseText\b)"
HASH = r"(?:\b(?:md5|sha1|sha224|sha256|sha384|sha512)\(|createHash\(\s*[\"'](?:md5|sha1|sha256|sha512)[\"'])"
RANDOM = r"(?:\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\(|\bMath\.random\(\))"
SENSITIVE = r"(?:token|secret|password|passwd|otp|nonce|salt|api_?key|session|reset)"
SHELL_FIX = 'pass the arguments as a list, without a shell: subprocess.run(["git", "log", ref]) / execFile("git", ["log", ref])'
EVAL_FIX = "never run text as code: parse it (json.loads, ast.literal_eval, JSON.parse) or map it to functions you wrote"
XSS_FIX = ("escape it, or sanitize it (DOMPurify.sanitize, bleach.clean) first: text a user typed would run as script in other users' browsers."
           " JSON-LD: JSON.stringify(data).replace(/</g, '\\u003c')")
# (rule, files it covers (regex on the path), what gives it away in an added line, the fix[, what else the file must hold]).
# The first rule that matches a line wins, so secrets go first: their line is never echoed whole.
RULES = [(name, re.compile(where), re.compile(rx), fix, re.compile(needs) if needs else None) for name, where, rx, fix, needs in [
    ("secrets", "",
     r"\bAKIA[0-9A-Z]{16}\b|\bsk-(?:ant-|proj-)?[\w-]{32,}|\b[rs]k_live_[0-9A-Za-z]{20,}|\bgh[pousr]_[0-9A-Za-z]{36}\b|\bgithub_pat_\w{60,}"
     r"|\bglpat-[\w-]{20,}|\bxox[abpr]-[0-9A-Za-z-]{10,}|\bAIza[\w-]{35}|\bnpm_[0-9A-Za-z]{36}\b|\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}"
     r"|\bSG\.[\w-]{22}\.[\w-]{43}\b|hooks\.slack\.com/services/T\w+/B\w+/\w+|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----",
     "read it from an environment variable, and revoke the key if this was ever pushed", None),
    ("silences-scanner", "",
     r"#\s*nosec\b|\bnosemgrep\b|\bgitleaks:allow\b|\bpragma:\s*allowlist\s+secret\b|#\s*noqa:\s*S\d|\bNOSONAR\b|\btrufflehog:ignore\b"
     r"|\bcheckov:skip\b|\btfsec:ignore\b|eslint-disable.*(?:\bsecurity/|\bno-eval\b|\bno-implied-eval\b|react/no-danger)",  # pwnstop: ignore (the rule itself)
     "silences a security scanner: fix what it found instead", None),
    ("sql-injection", CODE,
     rf"""(?i)\b[rb]?f"[^"]*\b{SQL}[^"]*{VALUE}\{{|\b[rb]?f'[^']*\b{SQL}[^']*{VALUE}\{{|(?<![\w$.])`[^`]*\b{SQL}[^`]*{VALUE}\$\{{"""
     rf"""|"[^"]*\b{SQL}[^"]*{VALUE}"\s*\+\s*\w|'[^']*\b{SQL}[^']*{VALUE}'\s*\+\s*\w"""
     rf"""|"[^"]*\b{SQL}[^"]*{VALUE}(?:%[sd]|\{{\w*\}})[^"]*"\s*(?:%\s*[\w(]|\.format\()|\bsprintf\(\s*"[^"]*\b{SQL}[^"]*{VALUE}%[sdv]""",
     'pass the values as query parameters: execute("SELECT ... WHERE id = %s", (uid,)) / query("... WHERE id = $1", [id])', None),
    ("shell-injection", PY,
     rf"""\bos\.(?:system|popen)\(\s*(?:[rb]?f["']|["'][^"']*["']{JOIN})|\bsubprocess\.\w+\((?=.*\bshell\s*=\s*True)\s*(?:[rb]?f["']|["'][^"']*["']{JOIN})""",
     SHELL_FIX, None),
    ("shell-injection", JS, r"""(?<![\w$])(?:exec|execSync)\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+\s*\w)""", SHELL_FIX, None),
    ("shell-injection", r"\.go$", r"""\bexec\.Command(?:Context)?\([^)]*"(?:ba|z)?sh"\s*,\s*"-c"\s*,\s*(?:[^)]*\+\s*\w|fmt\.Sprintf)""", SHELL_FIX, None),
    ("code-eval", PY, r"""(?<![\w.])(?:eval|exec)\(\s*(?!["')\s])""", EVAL_FIX, None),
    ("code-eval", JS, r"""(?<![\w.$])eval\(\s*(?!["')\s])|\bnew\s+Function\(|\bvm\.runIn\w*Context\(""", EVAL_FIX, None),
    ("jwt-unverified", CODE,
     r"""["']verify_signature["']\s*:\s*False|["']verify_exp["']\s*:\s*False|\balgorithms\s*[=:]\s*\[\s*["']none["']|\bignoreExpiration\s*:\s*true"""
     r"""|\bjwt\.decode\([^)]*\bverify\s*=\s*False""",
     'check the signature and the expiry: jwt.decode(token, key, algorithms=["HS256"]) / jwt.verify(token, key). Without it anyone can write their own token', None),
    ("tls-off", "",
     r"""\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[=:]\s*["']?0\b|\bInsecureSkipVerify\s*:\s*true\b"""
     r"""|\b_create_unverified_context\b|\bcheck_hostname\s*=\s*False\b|\bCERT_NONE\b|\bstrict-ssl\s*[=:]?\s*false\b|\bsslVerify\s*=?\s*false\b""",
     "keep certificate checks on: anyone on the network could read and change the traffic. For a self-signed certificate, point verify= / ca at it", None),
    ("unsafe-deserialize", PY,
     r"""\b(?:pickle|cPickle|_pickle|dill|marshal|jsonpickle)\.(?:loads?|decode|Unpickler)\(|\byaml\.(?:load|load_all)\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)"""
     r"""|\byaml\.unsafe_load(?:_all)?\(""",
     "this runs code hidden in the data: use json or yaml.safe_load for anything a user or another server sends, or only load files you made", None),
    ("cors-any-origin", CODE,
     r"""\ballow_origins\s*=\s*\[\s*["']\*["']|\borigins?\s*[:=]\s*(?:true\b|["']\*["'])|Access-Control-Allow-Origin["']?\s*[,:=]\s*["']\*|\bAllowAllOrigins\s*:\s*true"""
     r"""|\bAllowOrigins\s*:\s*\[\]string\{\s*"\*"|\bCORS\([^)]*origins\s*=\s*["']\*""",
     "list the sites that may call you: with credentials on, any site your users visit can call your API as them",
     r"""(?i)allow_credentials\s*=\s*True|credentials\s*:\s*true|supports_credentials\s*=\s*True|Allow-Credentials["']?\s*[,:=]\s*["']?true|AllowCredentials\s*:\s*true"""),
    ("weak-password-hash", CODE, rf"(?i){HASH}.*(?:password|passwd|pwd)|(?:password|passwd|pwd).*{HASH}",
     "hash passwords with a slow, salted hash: bcrypt, argon2 or scrypt (hashlib.scrypt / crypto.scrypt). md5 and sha are cracked by the billions per second", None),
    ("insecure-random", PYJS, rf"""(?i){SENSITIVE}\w*["']?\s*[:=][^=].*{RANDOM}|{RANDOM}.*{SENSITIVE}""",
     "use the secure generator for anything someone could guess: secrets.token_urlsafe(32) / crypto.randomUUID() / crypto.randomBytes(32)", None),
    ("xss", r"\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?)$",
     r"""\bdangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:(?!\s*(?:DOMPurify|purify|sanitize|xss)\w*[.(]|.*\.replace\(\s*/<)|\.(?:innerHTML|outerHTML)\s*\+?=.*""" + USER_TEXT
     + r"""|\binsertAdjacentHTML\(.*""" + USER_TEXT + r"""|\bdocument\.write(?:ln)?\(.*""" + USER_TEXT + r"""|\bv-html\s*=|\{@html(?!\s+(?:DOMPurify|sanitize))\s""", XSS_FIX, None),
    ("xss", r"\.(?:py|html?|jinja2?|j2)$", r"""\bmark_safe\(\s*(?!["'])|\bMarkup\(\s*(?:[rb]?f["']|[^)]*\+)|\|\s*safe\b|\{%\s*autoescape\s+(?:false|off)\b""", XSS_FIX, None),
    ("path-traversal", PYJS,
     rf"""\b(?:open|send_file|FileResponse|sendFile|readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|rmSync|join|resolve|Path)\([^)]*{INPUT}""",
     "don't build a file path from the request: a name like ../../etc/passwd walks out of your folder. Resolve it and check it's still inside, or look the name up in a list", None),
    ("ssrf", PYJS,
     rf"""\b(?:requests\.\w+|httpx\.\w+|urlopen|fetch|axios(?:\.\w+)?|got(?:\.\w+)?|https?\.(?:get|request)|session\.(?:get|post|request))\(\s*(?:[rb]?f["']\{{\s*|`\$\{{\s*)?{INPUT}""",
     "don't fetch an address the user picked: they'll point it at your internal network or the cloud metadata (169.254.169.254). Allow-list the hosts", None),
    ("debug-on", PY, r"""\.run\([^)]*\bdebug\s*=\s*True|\bFLASK_DEBUG\s*=\s*["']?1|\buse_debugger\s*=\s*True""",
     "turn the debugger off outside your machine: Werkzeug's debugger runs any Python a visitor types. Read it from an env var", None),
    ("actions-injection", r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$|(?:^|/)action\.ya?ml$",
     r"""^(?!\s*(?:-\s+)?(?!run:|script:)[\w-]+:\s*["']?\$\{\{).*\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)"""
     r"""|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|commits\b[^}]*\.(?:message|author)"""
     r"""|pages\b[^}]*\.page_name|workflow_run\.(?:head_branch|display_title))|github\.head_ref)\b""",
     'pass it through env: and quote it (env: TITLE: ${{ github.event.issue.title }}, then "$TITLE"): whoever opens an issue or PR writes this text, and here it runs as shell', None),
    ("world-writable", "", r"""\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+w|o\+w|a\+rwx|ugo\+rwx)\b|\bchmod(?:Sync)?\([^)]*\b0o?777\b""",
     "let only the owner write (755 for folders, 644 for files): 777 lets every user and process on the machine change it", None),
]]


def git(root, *args):
    """stdout of a git command run in `root`, or None if it fails (no git, not a repo, unknown ref)."""
    try:
        r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    except OSError:
        return None
    return r.stdout if r.returncode == 0 else None


def read(*paths):
    """The text of the files that exist, joined."""
    out = []
    for p in paths:
        try:
            out.append(p.read_text(errors="ignore"))
        except OSError:
            pass
    return "".join(out)


def load(f, default):
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError):
        return default


def find_root(path):
    """The git repo `path` is in, or `path`."""
    return next((d for d in [path, *path.parents] if (d / ".git").exists()), path)


def snapshot(root):
    """A commit with the working tree as it is now (tracked files), to compare with later. None without git."""
    ref = (git(root, "stash", "create") or "").strip()  # writes nothing to the stash, the index or the files
    return ref or (git(root, "rev-parse", "--verify", "-q", "HEAD") or "").strip() or None


def is_test(path):
    p = Path(path)
    return bool(TEST_NAME.search(p.name)) or bool(TEST_DIRS & set(p.parts[:-1]))


def added_lines(root, ref, rels):
    """{path: [(line number, text)]} for the lines added since commit `ref` (new files: all their lines)."""
    tracked = set((git(root, "ls-tree", "-r", "--name-only", ref, "--", *rels) or "").splitlines()) if rels and ref else set()
    diff = git(root, "diff", "--no-color", "--no-ext-diff", "--unified=0", "--relative", ref, "--", *sorted(tracked)) or "" if tracked else ""
    out, path, n = {}, None, 0
    for ln in diff.splitlines():
        if ln.startswith("+++ "):
            path = ln[6:] if ln.startswith("+++ b/") else None
        elif ln.startswith("@@"):
            n = int(re.search(r"\+(\d+)", ln)[1])
        elif ln.startswith("+") and path:
            out.setdefault(path, []).append((n, ln[1:]))
            n += 1
    for r in rels:
        f = root / r
        if r not in tracked and f.is_file() and f.stat().st_size < 1_000_000 and b"\0" not in f.read_bytes()[:8000]:
            out[r] = list(enumerate(read(f).splitlines(), 1))
    return out


def changed_since(root, since):
    """Files modified after `since`, whoever touched them (edit tools, shell commands, codegen)."""
    out = []
    for p in (git(root, "ls-files", "-co", "--exclude-standard", "-z") or "").split("\0"):
        try:
            if p and (root / p).stat().st_mtime > since:
                out.append(str(root / p))
        except OSError:
            pass
    return out


def git_changed(root, ref="HEAD"):
    """Files changed since `ref`, plus untracked ones."""
    out = set()
    for args in (["diff", "--name-only", "--relative", ref], ["ls-files", "-o", "--exclude-standard"]):
        out |= {str(root / ln) for ln in (git(root, *args) or "").splitlines() if ln}
    return sorted(out)


def match_line(path, text, whole=lambda: ""):
    """(rule, what, fix) for the first rule an added line breaks, or None. `whole()` gives the file's text, for the
    rules that need something else in it. Docs only get the secrets check, tests the secrets and silencers ones."""
    docs, test = DOCS.search(path), is_test(path)
    for name, where, rx, fix, needs in RULES:
        if (name != "secrets" and (docs or (test and name != "silences-scanner"))) or not where.search(path):
            continue
        m = rx.search(text)
        if m and (not needs or needs.search(whole())):
            return name, m.group(0)[:10] + "…" if name == "secrets" else text.strip()[:100], fix
    return None


def scan(root, ref, files, session=False):
    """[(path, line, rule, what, fix)]: the added lines that open a hole, and the .env files git would commit.
    `session`: an agent's changes, where a `pwnstop: ignore` it added is flagged instead of obeyed."""
    rels = [r for r in (os.path.relpath(f, root) for f in files)
            if not r.startswith("..") and not SKIP_DIRS & set(Path(r).parts) and not LOCKS.search(r)]
    found, texts = [], {}
    for path, lines in added_lines(root, ref, rels).items():
        if ENV_FILE.search(path):
            found.append((path, 0, "env-file", Path(path).name, ENV_FIX))
        for n, text in lines:
            if len(text) > 1000:  # minified or generated
                continue
            if IGNORE in text:
                if session:
                    found.append((path, n, "silences-scanner", text.strip()[:100], "silences pwnstop: fix the cause, or keep it and tell the user why"))
                continue
            hit = match_line(path, text, lambda p=path: texts.setdefault(p, read(root / p)))
            if hit:
                found.append((path, n, *hit))
    return found


def message(found, session=True):
    out = []
    for path, n, rule, what, fix in found[:20]:
        out += [f"{path}{f':{n}' if n else ''}  {rule}", f"  {what}", f"  → {fix}"]
    head = "pwnstop: these changes open a security hole. Fix them before finishing:" if session else f"pwnstop: {len(found)} security problem(s) in the changes:"
    tail = "\n\nA false alarm? Keep it and tell the user why in your final answer: pwnstop flags each one only once." if session else ""
    return head + "\n\n" + "\n".join(out) + tail


def agent_of(data):
    """Which agent sent the event, told apart by its payload (or the env it sets)."""
    if "cursor_version" in data or "workspace_roots" in data:
        return "cursor"
    if "turn_id" in data:
        return "codex"
    if "sessionId" in data or "toolName" in data:
        return "copilot"
    for env, name in (("GEMINI_PROJECT_DIR", "gemini"), ("CLAUDE_PROJECT_DIR", "claude")):
        if os.environ.get(env):
            return name
    return str(data.get("agent") or "other")


def reply(agent, error=None, notes=()):
    """Each agent's way to say "keep working". Claude Code also shows the user `notes`."""
    if agent == "cursor":
        out = {"followup_message": error} if error else {}
    elif error:
        out = {"decision": "block", "reason": error}
    elif notes and agent == "claude":
        out = {"systemMessage": "pwnstop: " + "; ".join(notes)}
    else:
        return 0
    print(json.dumps(out))
    return 0


def mark(sid, roots):
    """Start of a session, or of the next task after a stop: note the time and a git snapshot per project."""
    (STATE / f"{sid}.since").write_text(str(time.time()))
    (STATE / f"{sid}.refs").write_text(json.dumps({str(r): snapshot(r) for r in roots}))


def hook(event, data):
    """Answer an agent's hook event, in its own format."""
    agent = agent_of(data)
    env_root = os.environ.get("CLAUDE_PROJECT_DIR") or os.environ.get("GEMINI_PROJECT_DIR")
    paths = data.get("workspace_roots") or [env_root or data.get("cwd") or os.getcwd()]
    roots = sorted({find_root(Path(p).resolve()) for p in paths})
    roots = [r for r in roots if (r / ".git").exists()]
    if not roots:
        return reply(agent)
    sid = re.sub(r"[^\w-]", "_", str(data.get("conversation_id") or data.get("session_id") or data.get("sessionId") or "default"))
    STATE.mkdir(parents=True, exist_ok=True)
    since_f, flagged_f = STATE / f"{sid}.since", STATE / f"{sid}.flagged"
    if event == "start" or not since_f.exists():
        mark(sid, roots)
        return reply(agent)
    if data.get("status") in ("aborted", "error"):
        return reply(agent)
    since, refs, flagged = float(since_f.read_text()), load(STATE / f"{sid}.refs", {}), set(load(flagged_f, []))
    found = [f for r in roots for f in scan(r, refs.get(str(r)), changed_since(r, since), session=True)]
    keys = {f"{p}:{rule}:{what}" for p, _, rule, what, _ in found}
    new = [f for f in found if f"{f[0]}:{f[2]}:{f[3]}" not in flagged]
    flagged_f.write_text(json.dumps(sorted(flagged | keys)))
    if new:
        return reply(agent, message(new))
    mark(sid, roots)
    return reply(agent, notes=[f"kept after being told: {p}{f':{n}' if n else ''} {rule}" for p, n, rule, *_ in found[:5]])


def installed_version():
    try:
        from importlib.metadata import version
        return version("pwnstop")
    except ImportError:  # PackageNotFoundError too: run from a checkout
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    if cmd in ("start", "verify"):
        try:
            data = json.load(sys.stdin)
        except ValueError:
            data = {}
        try:
            return hook(cmd, data if isinstance(data, dict) else {})
        except Exception as e:  # a bug here must not stop the agent
            print(f"pwnstop: internal error, skipped: {e!r}", file=sys.stderr)
            return 0
    if cmd in ("--version", "-V", "version"):
        print(f"pwnstop {installed_version() or '(not installed: run from source)'}")
        return 0
    if cmd == "check":
        root, args, ref = find_root(Path.cwd().resolve()), argv[1:], "HEAD"
        if args[:1] == ["--base"] and len(args) > 1:  # in CI: everything the branch changed since it left <ref>
            ref, args = (git(root, "merge-base", args[1], "HEAD") or args[1]).strip(), args[2:]
        files = [str(Path(a).resolve()) for a in args] or git_changed(root, ref)
        found = scan(root, ref if git(root, "rev-parse", "--verify", "-q", ref) else None, files)
        print(message(found, session=False) if found else f"pwnstop: no security problems in {len(files)} changed file(s).")
        return 1 if found else 0
    print(__doc__.strip())
    return 0 if cmd in ("", "-h", "--help", "help") else 2


if __name__ == "__main__":
    sys.exit(main())
