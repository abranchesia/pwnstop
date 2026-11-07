# Security policy

pwnstop runs inside your agent's hooks and reads text strangers wrote, so a hole in it matters twice.

## Report privately

Use [GitHub's private reporting](https://github.com/abranchesia/pwnstop/security/advisories/new) for:

- **A vulnerability in pwnstop itself.** A file name, a line, a hook payload or a PR that makes pwnstop run code, write outside its state folder, leak what it reads, or slip a workflow command into a CI log.
- **A way around a rule that exists.** A command the guard blocks in one spelling and lets through in an obvious other one, or a hole the stop check misses when it's written a common way.

Say which version (`pwnstop --version`), the agent if one was involved, and the shortest command or file that shows it. The fix ships in a new release, with credit if you want it.

## Open an issue instead

- [A false alarm](https://github.com/abranchesia/pwnstop/issues/new?template=false-alarm.yml).
- [A dangerous pattern no rule covers yet](https://github.com/abranchesia/pwnstop/issues/new?template=new-rule.yml).

## Supported versions

Only the latest release gets fixes. Update with `uv tool upgrade pwnstop` (or `pipx upgrade pwnstop`).

## What pwnstop doesn't promise

It matches patterns one line at a time and is not a sandbox: someone set on getting past it can, for example by downloading a script first and running it later. It catches what agents write and what injected prompts usually ask for. See [What it is not](https://github.com/abranchesia/pwnstop#what-it-is-not).
