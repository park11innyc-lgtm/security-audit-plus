# security-audit-plus

A source-first security audit skill for coding agents, with a threat-intel loop added. It watches advisories and security news, matches them against the dependencies you actually have pinned, and turns each hit into a focused review of your own code.

The audit workflow itself comes from [Cloudflare's security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). See `UPSTREAM.md` for exactly what changed.

## What the intel scanner does

```bash
python3 intel/intel_scan_v1.py                       # scan, report what's new, remember it
python3 intel/intel_scan_v1.py --settings my.json    # your own roots, keywords and feeds
python3 -m unittest discover -s intel/tests          # offline tests, no network
```

1. **Inventory**: reads `package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt` (pinned `==` only), `poetry.lock`, `uv.lock` and `Cargo.lock` under each root.
2. **Match**: queries [OSV.dev](https://osv.dev) in batches and pulls severity and fixed versions.
3. **Prioritize**: an advisory whose CVE is on the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list is marked as exploited in the wild and sorted first.
4. **Watch**: new KEV entries and security-news headlines that mention your stack keywords.
5. **Check yourself**: for every affected lockfile, it writes a focused-audit brief for the agent to run in guidance mode. Is the vulnerable path reachable from untrusted input, and what is the smallest fix?
6. **Learn**: a new attack class becomes a proposed hunt question in `skill/LEARNED_PATTERNS.md`, merged by a human.

Exit codes: `0` quiet, `2` new findings, `3` a source was unreadable. A blind run is never reported as an all-clear.

## Design choices

- **Python standard library only.** Nothing to install, nothing to audit in its own supply chain.
- **Feed text is untrusted.** Markup and control characters are stripped before anything reaches the report. Only `https` links are kept. Feeds that declare a DTD are refused, which blocks entity-expansion attacks. The agent never edits its own instructions from feed content.
- **Absence of evidence is not evidence of absence.** Unreadable sources and unparsable lockfiles are listed under "PARTLY BLIND".
- **Tunables live in `intel/SETTINGS_v1.json`.** Roots, lookback window, keywords and feeds are all there. Changing them needs no code edit.

## Run it daily

`.github/workflows/intel_v1.yml` runs the tests and the scan every day and keeps one living issue. It opens or updates the issue when there are findings and closes it on a quiet day. The workflow has read-only contents access, and its checkout action is pinned by commit SHA.

## Install as a Claude Code skill

```bash
cp -r skill ~/.claude/skills/security-audit-plus
cp -r intel ~/.claude/skills/security-audit-plus/intel
```
