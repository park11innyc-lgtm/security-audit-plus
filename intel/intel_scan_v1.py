#!/usr/bin/env python3
"""intel_scan_v1 - threat-intel scanner for the security-audit skill.

Builds a dependency inventory from lockfiles under the configured roots, checks it
against OSV.dev, flags anything also on the CISA Known Exploited Vulnerabilities
list, and scans security news feeds for your stack keywords. Reports only what is
new since the last run. Stdlib only.

Exit codes: 0 = quiet, 2 = new findings, 3 = a source could not be read (blind).
A blind run never counts as an all-clear.

Feed text is untrusted data. It is sanitized before it reaches the report and is
never treated as instructions.
"""
import argparse, json, os, re, stat, sys, unicodedata, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "security-audit-plus-intel/1"
MAX_BYTES = 8 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", ".next", "dist", "build"}
OSV_BATCH = 500


# ---------- network ----------

class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.URLError(f"refused redirect to non-https URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect)


def fetch(url, data=None, timeout=45):
    """GET (or POST JSON) with a size cap. Raises on HTTP error or oversize body."""
    if not url.startswith("https://"):
        raise ValueError("only https sources are allowed")
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, **({"Content-Type": "application/json"} if body else {})})
    with _OPENER.open(req, timeout=timeout) as r:
        raw = r.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("response over size cap")
    return raw


# ---------- inventory ----------

def read(path):
    """Regular files only (no FIFOs, devices or symlinks), capped at MAX_BYTES."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > MAX_BYTES:
        raise ValueError("file over size cap")
    with open(path, encoding="utf-8") as f:
        return f.read(MAX_BYTES)


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


SAFE_NAME = re.compile(r"^[@A-Za-z0-9][A-Za-z0-9@/._~+-]{0,213}$")


def _add(inv, eco, name, ver, path):
    if not (isinstance(name, str) and isinstance(ver, str)):
        return
    if SAFE_NAME.match(name) and re.match(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$", ver):
        inv.setdefault((eco, name, ver), set()).add(path)


def parse_npm_lock(path, inv):
    d = json.loads(read(path))
    pkgs = d.get("packages") if isinstance(d, dict) else None
    for key, meta in (pkgs if isinstance(pkgs, dict) else {}).items():
        if not key or not isinstance(meta, dict) or meta.get("link"):
            continue
        name = meta.get("name") or key.split("node_modules/")[-1]
        _add(inv, "npm", name, meta.get("version"), path)
    def walk(deps):
        for name, meta in (deps if isinstance(deps, dict) else {}).items():
            if isinstance(meta, dict):
                _add(inv, "npm", name, meta.get("version"), path)
                walk(meta.get("dependencies"))
    if isinstance(d, dict) and not pkgs:
        walk(d.get("dependencies"))


PNPM_KEY = re.compile(r"^  '?/?((?:@[^/@\s']+/)?[^@\s'/]+)[@/]([0-9][^():'\s]*)")

def parse_pnpm_lock(path, inv):
    in_pkgs = False
    for line in read(path).splitlines(True):
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_pkgs = True
            continue
        if in_pkgs and re.match(r"^\S", line):
            in_pkgs = False
        if in_pkgs:
            m = PNPM_KEY.match(line)
            if m:
                _add(inv, "npm", m.group(1), m.group(2), path)


def parse_requirements(path, inv):
    for line in read(path).splitlines(True):
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)", line)
        if m:
            _add(inv, "PyPI", m.group(1).lower(), m.group(2), path)


def parse_toml_lock(path, inv, eco):
    """poetry.lock, uv.lock and Cargo.lock all use [[package]] blocks with name/version."""
    name = ver = None
    for line in read(path).splitlines(True):
        if line.startswith("[[package]]"):
            if name and ver:
                _add(inv, eco, name.lower() if eco == "PyPI" else name, ver, path)
            name = ver = None
            continue
        m = re.match(r'^(name|version)\s*=\s*"([^"]+)"', line)
        if m:
            if m.group(1) == "name":
                name = m.group(2)
            else:
                ver = m.group(2)
    if name and ver:
        _add(inv, eco, name.lower() if eco == "PyPI" else name, ver, path)


PARSERS = {
    "package-lock.json": parse_npm_lock,
    "npm-shrinkwrap.json": parse_npm_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "poetry.lock": lambda p, i: parse_toml_lock(p, i, "PyPI"),
    "uv.lock": lambda p, i: parse_toml_lock(p, i, "PyPI"),
    "Cargo.lock": lambda p, i: parse_toml_lock(p, i, "crates.io"),
}


SAFE_PATH = re.compile(r"^[A-Za-z0-9 /._~+@-]+$")


def inventory(roots, errors):
    inv = {}
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            errors.append(f"root not found: {root}")
            continue
        for r, ds, fs in os.walk(root, onerror=lambda e: errors.append(f"could not read {e.filename}: {type(e).__name__}")):
            ds[:] = [d for d in ds if d not in SKIP_DIRS]
            for f in fs:
                p = os.path.join(r, f)
                if f not in PARSERS and not re.match(r"^requirements[\w.-]*\.txt$", f):
                    continue
                if not SAFE_PATH.match(p):
                    errors.append("skipped a lockfile whose path has unsafe characters")
                    continue
                try:
                    if f in PARSERS:
                        PARSERS[f](p, inv)
                    elif re.match(r"^requirements[\w.-]*\.txt$", f):
                        parse_requirements(p, inv)
                except Exception as e:
                    errors.append(f"could not parse {p}: {type(e).__name__}")
    return inv


# ---------- sources ----------

def osv_check(inv, errors):
    """Returns {(eco,name,ver): [vuln ids]}."""
    keys = sorted(inv)
    hits = {}
    for i in range(0, len(keys), OSV_BATCH):
        chunk = keys[i:i + OSV_BATCH]
        q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        try:
            res = json.loads(fetch("https://api.osv.dev/v1/querybatch", q)).get("results", [])
        except Exception as e:
            errors.append(f"OSV batch {i // OSV_BATCH + 1} unreadable: {type(e).__name__}")
            continue
        if len(res) != len(chunk):
            errors.append(f"OSV batch {i // OSV_BATCH + 1} returned {len(res)} of {len(chunk)} results")
        for k, r in zip(chunk, res):
            ids = [v["id"] for v in (r.get("vulns") or [])]
            if ids:
                hits[k] = ids
    return hits


def vkey(v):
    """Rough version order: numeric parts compare as numbers, pre-release tags sort first."""
    return [(0, int(x), "") if x.isdigit() else (-1, 0, x) for x in re.split(r"[.+-]", v)]


def osv_details(vid, eco, name, ver, cache, errors):
    """Advisory facts for one package. Returns None if the advisory could not be read;
    failures are not cached, so the next run retries."""
    if vid not in cache:
        try:
            cache[vid] = json.loads(fetch(f"https://api.osv.dev/v1/vulns/{urllib.request.quote(vid)}"))
        except Exception as e:
            errors.append(f"OSV detail {vid} unreadable: {type(e).__name__}")
            return None
    d = cache[vid]
    mine = [a for a in d.get("affected", []) if (a.get("package") or {}).get("ecosystem") == eco
            and (a.get("package") or {}).get("name", "").lower() == name.lower()] or d.get("affected", [])
    sev = ""
    for src in (d.get("database_specific") or {}, *[a.get("database_specific") or {} for a in mine]):
        if src.get("severity"):
            sev = str(src["severity"]).upper()
            break
    fixed = sorted({ev["fixed"] for a in mine for rg in a.get("ranges", []) for ev in rg.get("events", []) if "fixed" in ev}, key=vkey)
    above = [f for f in fixed if vkey(f) > vkey(ver)]
    return {"summary": clean(d.get("summary", "")), "aliases": d.get("aliases", []), "severity": sev,
            "fix": above[0] if above else "", "fixed": fixed}


def kev_feed(errors):
    try:
        return json.loads(fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")).get("vulnerabilities", [])
    except Exception as e:
        errors.append(f"CISA KEV unreadable: {type(e).__name__}")
        return None


def parse_feed(raw):
    """RSS 2.0 or Atom -> [(title, link, published datetime|None, summary)]. Rejects DTDs."""
    # Entities can only be declared in a DTD, and a DTD can only sit in the prolog (before the
    # root element). Refusing any DTD there blocks entity-expansion attacks; HTML in CDATA is fine.
    body = re.sub(rb"<!--.*?-->|<\?.*?\?>", b"", raw, flags=re.S)
    m = re.search(rb"<[A-Za-z_]", body)
    if m is None or b"<!DOCTYPE" in body[:m.start()].upper() or b"<!ENTITY" in body[:m.start()].upper():
        raise ValueError("feed has no root element or declares a DTD; refused")
    root = ET.fromstring(raw)
    out = []
    strip = lambda t: re.sub(r"^\{[^}]+\}", "", t)
    for el in root.iter():
        if strip(el.tag) not in ("item", "entry"):
            continue
        f = {strip(c.tag): c for c in el}
        title = (f.get("title").text if f.get("title") is not None else "") or ""
        link = ""
        if f.get("link") is not None:
            link = f["link"].get("href") or (f["link"].text or "")
        date = None
        for k in ("pubDate", "published", "updated", "date"):
            if f.get(k) is not None and f[k].text:
                date = parse_date(f[k].text.strip())
                if date:
                    break
        summ = ""
        for k in ("description", "summary", "content"):
            if f.get(k) is not None and f[k].text:
                summ = f[k].text
                break
        out.append((title, link.strip(), date, summ))
    return out


def parse_date(s):
    try:
        d = parsedate_to_datetime(s)
    except Exception:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ---------- helpers ----------

SAFE_LINK = re.compile(r"https://[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9._~%/?=&+,;:@-]*)?")


def clean(text, limit=220):
    """Untrusted text -> one safe line: no tags, no control chars, no markdown/HTML active syntax."""
    t = re.sub(r"<[^>]*>", " ", text or "")
    t = "".join(" " if unicodedata.category(c) in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp") else c for c in t)
    t = re.sub(r"[`*_\[\]<>|#!()]", "", t)
    t = t.replace("@", "(at)")   # no @mentions in a posted issue
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit] + ("..." if len(t) > limit else "")


def kw_regex(words):
    words = [w for w in words if w.strip()]
    if not words:
        return None
    return re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)) + r")(?![A-Za-z0-9])", re.I)


def load_json(p, default):
    try:
        return json.loads(read(p))
    except FileNotFoundError:
        return default


# ---------- main ----------

def run(settings, state, now):
    errors, new = [], {"deps": [], "kev": [], "news": []}
    seen = set(state.get("seen", []))
    kev_flagged = set(state.get("kev_flagged", []))
    aliases = dict(state.get("aliases", {}))
    since = now - timedelta(days=settings.get("lookback_days", 3))
    kw = kw_regex(settings.get("stack_keywords", []))

    inv = inventory(settings.get("roots", []), errors)
    kev = kev_feed(errors)
    kev_cves = {v.get("cveID") for v in (kev or [])}

    hits = osv_check(inv, errors) if inv else {}
    cache = {}
    for (eco, name, ver), ids in sorted(hits.items()):
        for vid in ids:
            key = f"dep:{eco}:{name}:{ver}:{vid}"
            if key in seen:
                # Already reported. Re-report only if its CVE has since joined the exploited list.
                if key in kev_flagged or not (set(aliases.get(key, [])) | {vid}) & kev_cves:
                    continue
            d = osv_details(vid, eco, name, ver, cache, errors)
            files = sorted(os.path.relpath(p, os.path.expanduser("~")) for p in inv[(eco, name, ver)])
            if d is None:
                # Report it, but leave it unseen so the next run fills in severity, fix and KEV status.
                new["deps"].append({"key": key, "eco": eco, "name": name, "version": ver, "id": vid, "severity": "",
                                    "fix": "", "fixed": [], "summary": "details unavailable, retried next run",
                                    "kev": [], "files": files, "incomplete": True})
                continue
            exploited = sorted(a for a in d["aliases"] + [vid] if a in kev_cves)
            new["deps"].append({"key": key, "eco": eco, "name": name, "version": ver, "id": vid,
                                "severity": d["severity"], "fix": d["fix"], "fixed": d["fixed"], "summary": d["summary"],
                                "kev": exploited, "files": files, "aliases": d["aliases"][:20]})

    for v in kev or []:
        added = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00")
        text = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')}"
        key = f"kev:{v.get('cveID')}"
        if added and added >= since and kw and kw.search(text) and key not in seen:
            new["kev"].append({"key": key, "cve": v.get("cveID"), "what": clean(text), "due": v.get("dueDate", ""),
                               "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known"})

    for feed in settings.get("news_feeds", []):
        try:
            items = parse_feed(fetch(feed["url"]))
        except Exception as e:
            errors.append(f"feed {feed.get('name', feed['url'])} unreadable: {type(e).__name__}")
            continue
        for title, link, date, summ in items:
            if date and date < since:
                continue
            m = kw.search(f"{title} {summ}" if settings.get("match_summary") else title) if kw else None
            key = f"news:{link or title}"
            if m and key not in seen and SAFE_LINK.fullmatch(link):
                new["news"].append({"key": key, "source": feed.get("name", ""), "title": clean(title),
                                    "link": link, "match": m.group(1)})

    cap = int(settings.get("max_news_items", 40))
    if len(new["news"]) > cap:
        errors.append(f"news capped at {cap} of {len(new['news'])} items; the rest are reported next run")
        new["news"] = new["news"][:cap]
    for k in ("deps", "kev", "news"):
        seen.update(x["key"] for x in new[k] if not x.get("incomplete"))
    for d in new["deps"]:
        if not d.get("incomplete"):
            aliases[d["key"]] = d.get("aliases", [])
            if d["kev"]:
                kev_flagged.add(d["key"])
    stats = {"packages": len(inv), "vulnerable_packages": len(hits), "kev_entries": len(kev or [])}
    return new, errors, {"seen": sorted(seen), "kev_flagged": sorted(kev_flagged), "aliases": aliases,
                         "last_run": now.isoformat()}, stats


def briefs(new):
    """One focused-audit brief per affected lockfile: the 'check yourself' step."""
    by_file = {}
    for d in new["deps"]:
        for f in d["files"]:
            by_file.setdefault(f, []).append(d)
    out = []
    for f, ds in sorted(by_file.items()):
        lines = ", ".join(f"{d['name']} {d['version']} ({d['id']})" for d in ds[:8])
        out.append(f"- `{f}`: use the security-audit skill in guidance mode. For {lines}: confirm whether the vulnerable "
                   f"code path is reachable from an untrusted input in this project, then upgrade to the fixed version. "
                   f"Fails if the upgrade changes behaviour the tests cover.")
    return out


def render(new, errors, stats, now):
    L = [f"# Threat intel: {now:%Y-%m-%d %H:%M} UTC", "",
         f"Scanned {stats['packages']} pinned packages; {stats['vulnerable_packages']} have known advisories; KEV list size {stats['kev_entries']}.", ""]
    if errors:
        L += ["## PARTLY BLIND: these sources could not be read, so this is not an all-clear", ""] + [f"- {e}" for e in errors] + [""]
    deps = sorted(new["deps"], key=lambda d: (not d["kev"], d["severity"] not in ("CRITICAL", "HIGH"), d["name"]))
    if deps:
        L += ["## New advisories in your dependencies", "", "| Package | Advisory | Severity | Exploited (KEV) | Upgrade to | Where |", "|---|---|---|---|---|---|"]
        for d in deps[:150]:
            d = {**d, "id": clean(d["id"], 60), "fix": clean(d["fix"], 40), "fixed": [clean(x, 40) for x in d["fixed"]],
                 "severity": clean(d["severity"], 20), "kev": [clean(x, 30) for x in d["kev"]]}
            L.append(f"| {d['eco']} {d['name']} {d['version']} | [{d['id']}](https://osv.dev/vulnerability/{d['id']}) {d['summary'][:90]} | "
                     f"{d['severity'] or '?'} | {', '.join(d['kev']) or 'no'} | {d['fix'] or ('no fix above installed' if d['fixed'] else '?')} | {'; '.join(d['files'][:2])}{f' (+{len(d["files"]) - 2} more)' if len(d['files']) > 2 else ''} |")
        if len(deps) > 150:
            L.append(f"| ... | {len(deps) - 150} more in the JSON report | | | | |")
        L += ["", "## Focused audits to run", ""] + briefs(new) + [""]
    if new["kev"]:
        L += ["## Newly exploited in the wild (CISA KEV) matching your stack", ""]
        L += [f"- {k['cve']}: {k['what']} (federal due date {k['due']}{', used by ransomware' if k['ransomware'] else ''})" for k in new["kev"]] + [""]
    if new["news"]:
        L += ["## Security news mentioning your stack", ""]
        L += [f"- [{n['title']}]({n['link']}) ({n['source']}, matched \"{clean(n['match'], 40)}\")" for n in new["news"]] + [""]
    if not (deps or new["kev"] or new["news"] or errors):
        L += ["Nothing new since the last run."]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--settings", default=os.path.join(HERE, "SETTINGS_v1.json"))
    ap.add_argument("--state", default=os.path.join(HERE, "state", "seen_v1.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "reports"))
    ap.add_argument("--no-save", action="store_true", help="do not update the seen-state file")
    a = ap.parse_args(argv)

    settings = load_json(a.settings, None)
    if settings is None:
        print(f"settings not found: {a.settings}", file=sys.stderr)
        return 3
    now = datetime.now(timezone.utc)
    new, errors, state, stats = run(settings, load_json(a.state, {}), now)
    report = render(new, errors, stats, now)

    os.makedirs(a.out, exist_ok=True)
    stamp = now.strftime("%Y%m%d-%H%M")
    write(os.path.join(a.out, f"intel_{stamp}.md"), report + "\n")
    write(os.path.join(a.out, f"intel_{stamp}.json"), json.dumps({"new": new, "errors": errors, "stats": stats}, indent=1))
    if not a.no_save:
        os.makedirs(os.path.dirname(a.state), exist_ok=True)
        tmp = a.state + ".tmp"
        write(tmp, json.dumps(state, indent=0))
        os.replace(tmp, a.state)
    print(report)
    if errors:
        return 3
    return 2 if any(new.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
