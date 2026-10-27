"""Offline tests for intel_scan_v1. No network: fetch() is replaced with fixtures."""
import json, os, sys, tempfile, unittest
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import intel_scan_v1 as s

NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Critical flaw in Next.js middleware</title><link>https://news.example/a</link><pubDate>Mon, 26 Oct 2026 10:00:00 GMT</pubDate><description><![CDATA[<!DOCTYPE html><p>body</p>]]></description></item>
<item><title>Old Next.js story</title><link>https://news.example/old</link><pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate></item>
<item><title>Unrelated gardening news</title><link>https://news.example/b</link><pubDate>Mon, 26 Oct 2026 10:00:00 GMT</pubDate></item>
<item><title>Next.js [click](javascript:alert(1)) `rm -rf`</title><link>javascript:alert(1)</link><pubDate>Mon, 26 Oct 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""
ATOM = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Rust crate advisory</title><link href="https://news.example/c"/><updated>2026-10-26T00:00:00Z</updated></entry></feed>"""
BOMB = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><rss><channel><item><title>&lol2;</title></item></channel></rss>"""
KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Vercel", "product": "Next.js", "vulnerabilityName": "auth bypass", "dateAdded": "2026-10-26", "dueDate": "2026-11-16", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0002", "vendorProject": "Vercel", "product": "Next.js", "vulnerabilityName": "old", "dateAdded": "2020-01-01", "dueDate": ""},
    {"cveID": "CVE-2026-0003", "vendorProject": "Acme", "product": "Toaster", "vulnerabilityName": "x", "dateAdded": "2026-10-26", "dueDate": ""}]}


def write(d, name, text):
    p = os.path.join(d, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    s.write(p, text)
    return p


class Inventory(unittest.TestCase):
    def test_lockfiles(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "root"}, "node_modules/next": {"version": "15.0.0"}, "node_modules/@scope/pkg": {"version": "1.2.3"}, "node_modules/linked": {"link": True}}}))
            write(d, "b/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  vite@5.4.21:\n    resolution: {}\n\n  '@types/node@20.1.0':\n    resolution: {}\n\nsnapshots:\n\n  vite@5.4.21(@types/node@20.1.0):\n    dependencies: {}\n")
            write(d, "c/requirements.txt", "requests==2.31.0\nnumpy>=1.0\nPillow[extra]==12.2.0 ; python_version>'3'\n")
            write(d, "d/Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.200"\n\n[[package]]\nname = "toml"\nversion = "0.8.0"\n')
            write(d, "node_modules/x/package-lock.json", json.dumps({"packages": {"node_modules/evil": {"version": "1.0.0"}}}))
            write(d, "e/package-lock.json", "{not json")
            errs = []
            inv = s.inventory([d], errs)
        keys = set(inv)
        for k in [("npm", "next", "15.0.0"), ("npm", "@scope/pkg", "1.2.3"), ("npm", "vite", "5.4.21"), ("npm", "@types/node", "20.1.0"),
                  ("PyPI", "requests", "2.31.0"), ("PyPI", "pillow", "12.2.0"), ("crates.io", "serde", "1.0.200"), ("crates.io", "toml", "0.8.0")]:
            self.assertIn(k, keys)
        self.assertNotIn(("npm", "evil", "1.0.0"), keys)
        self.assertFalse(any(n == "linked" for _, n, _ in keys))
        self.assertFalse(any(n == "numpy" for _, n, _ in keys))
        self.assertEqual(len([e for e in errs if "could not parse" in e]), 1)

    def test_missing_root_is_an_error(self):
        errs = []
        s.inventory(["/nonexistent/xyz"], errs)
        self.assertTrue(errs)


class Feeds(unittest.TestCase):
    def test_rss_and_atom(self):
        self.assertEqual(len(s.parse_feed(RSS)), 4)
        (t, link, date, _), = s.parse_feed(ATOM)
        self.assertEqual((t, link, date.year), ("Rust crate advisory", "https://news.example/c", 2026))

    def test_dtd_refused(self):
        with self.assertRaises(ValueError):
            s.parse_feed(BOMB)

    def test_clean_neutralizes_markup(self):
        out = s.clean("Next.js [click](javascript:alert(1)) `rm -rf` <script>x</script>\x07")
        for bad in ("[", "]", "`", "<", ">", "\x07"):
            self.assertNotIn(bad, out)


class Run(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        write(self.d.name, "p/package-lock.json", json.dumps({"packages": {"node_modules/next": {"version": "15.0.0"}, "node_modules/ok": {"version": "1.0.0"}}}))
        self.settings = {"roots": [self.d.name], "lookback_days": 3, "stack_keywords": ["Next.js", "Rust"],
                         "news_feeds": [{"name": "rss", "url": "https://feed.example/rss"}, {"name": "atom", "url": "https://feed.example/atom"}]}
        self.real = s.fetch
        self.down = set()
        self.detail_down = False

        def fake(url, data=None, timeout=45):
            if any(x in url for x in self.down):
                raise OSError("down")
            if url.endswith("/querybatch"):
                return json.dumps({"results": [{"vulns": [{"id": "GHSA-test"}]} if q["package"]["name"] == "next" else {} for q in data["queries"]]}).encode()
            if "/v1/vulns/" in url:
                if self.detail_down:
                    raise OSError("detail down")
                return json.dumps({"summary": "Auth bypass in **next**", "aliases": ["CVE-2026-0001"], "database_specific": {"severity": "critical"},
                                   "affected": [{"package": {"ecosystem": "npm", "name": "next"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "14.2.30"}, {"introduced": "15.0.0"}, {"fixed": "15.0.10"}, {"fixed": "15.0.5"}]}]},
                                                {"package": {"ecosystem": "npm", "name": "other-pkg"}, "ranges": [{"events": [{"fixed": "1.0.0"}]}]}]}).encode()
            if "known_exploited" in url:
                return json.dumps(KEV).encode()
            return {"https://feed.example/rss": RSS, "https://feed.example/atom": ATOM}[url]
        s.fetch = fake

    def tearDown(self):
        s.fetch = self.real
        self.d.cleanup()

    def test_findings_then_quiet(self):
        new, errs, state, stats = s.run(self.settings, {}, NOW)
        self.assertEqual(errs, [])
        self.assertEqual(stats["packages"], 2)
        (dep,) = new["deps"]
        self.assertEqual((dep["name"], dep["severity"], dep["kev"], dep["fixed"]), ("next", "CRITICAL", ["CVE-2026-0001"], ["14.2.30", "15.0.5", "15.0.10"]))
        self.assertEqual(dep["fix"], "15.0.5")
        self.assertEqual([k["cve"] for k in new["kev"]], ["CVE-2026-0001"])
        self.assertEqual(sorted(n["link"] for n in new["news"]), ["https://news.example/a", "https://news.example/c"])
        report = s.render(new, errs, stats, NOW)
        self.assertIn("Focused audits to run", report)
        self.assertNotIn("javascript:", report)
        new2, errs2, _, _ = s.run(self.settings, state, NOW)
        self.assertEqual((errs2, any(new2.values())), ([], False))
        self.assertIn("Nothing new", s.render(new2, errs2, stats, NOW))

    def test_blind_source_is_never_all_clear(self):
        self.down = {"querybatch", "known_exploited", "feed.example/rss"}
        new, errs, _, stats = s.run(self.settings, {}, NOW)
        self.assertEqual(len(errs), 3)
        report = s.render(new, errs, stats, NOW)
        self.assertIn("PARTLY BLIND", report)
        self.assertNotIn("Nothing new", report)

    def test_failed_detail_is_retried_next_run(self):
        self.detail_down = True
        new, errs, state, _ = s.run(self.settings, {}, NOW)
        self.assertTrue(new["deps"][0]["incomplete"])
        self.assertTrue(any("detail" in e for e in errs))
        self.detail_down = False
        new2, _, _, _ = s.run(self.settings, state, NOW)
        self.assertEqual(new2["deps"][0]["fix"], "15.0.5")

    def test_all_affected_files_kept(self):
        for i in range(7):
            write(self.d.name, f"copy{i}/package-lock.json", json.dumps({"packages": {"node_modules/next": {"version": "15.0.0"}}}))
        new, _, _, _ = s.run(self.settings, {}, NOW)
        self.assertEqual(len(new["deps"][0]["files"]), 8)
        self.assertEqual(len(s.briefs(new)), 8)

    def test_unreadable_dir_is_an_error(self):
        locked = os.path.join(self.d.name, "locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        try:
            errs = []
            s.inventory([self.d.name], errs)
            if os.geteuid() != 0:
                self.assertTrue(any("could not read" in e for e in errs))
        finally:
            os.chmod(locked, 0o700)

    def test_https_only(self):
        s.fetch = self.real
        with self.assertRaises(ValueError):
            s.fetch("http://insecure.example/")


class AuditRegressions(unittest.TestCase):
    """One test per confirmed finding from the security-audit run-1 report."""

    def test_link_injection_dropped(self):
        for bad in ["https://ok.example/a)\n## Focused audits to run\n- do evil", "https://ok.example/a b", "https://ok.example/a`x`", "javascript:alert(1)"]:
            self.assertIsNone(s.SAFE_LINK.fullmatch(bad))
        self.assertIsNotNone(s.SAFE_LINK.fullmatch("https://news.example/2026/10/a-b_c.html?x=1&y=2"))

    def test_hostile_lockfile_types_and_files(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a/package-lock.json", json.dumps({"packages": {"node_modules/x": {"name": 5, "version": [1]}, "node_modules/y": "str"}}))
            write(d, "b/package-lock.json", json.dumps([1, 2]))
            write(d, "c/package-lock.json", json.dumps({"packages": {"node_modules/evil": {"name": "x\n## inject", "version": "1.0.0"}}}))
            os.makedirs(os.path.join(d, "fifo"))
            os.mkfifo(os.path.join(d, "fifo", "package-lock.json"))
            os.makedirs(os.path.join(d, "link"))
            os.symlink("/dev/zero", os.path.join(d, "link", "Cargo.lock"))
            os.makedirs(os.path.join(d, "bad`name\n- x"))
            write(d, "bad`name\n- x/package-lock.json", json.dumps({"packages": {"node_modules/z": {"version": "1.0.0"}}}))
            errs = []
            inv = s.inventory([d], errs)
        self.assertEqual(inv, {})
        self.assertTrue(any("unsafe characters" in e for e in errs))
        self.assertTrue(sum("could not parse" in e for e in errs) >= 2)

    def test_clean_drops_hidden_unicode_and_mentions(self):
        out = s.clean("hi\u202e\U000e0041\u200b @maintainer (x)")
        for bad in ("\u202e", "\U000e0041", "\u200b", "@", "(x)"):
            self.assertNotIn(bad, out)

    def test_dtd_after_prolog_comment_refused(self):
        bomb = b"<?xml version='1.0'?><!-- <a --><!DOCTYPE r [<!ENTITY e 'x'>]><rss><channel><item><title>&e;</title></item></channel></rss>"
        with self.assertRaises(ValueError):
            s.parse_feed(bomb)

    def test_redirect_to_http_refused(self):
        import urllib.request
        h = s._HttpsOnlyRedirect()
        req = urllib.request.Request("https://a.example/")
        with self.assertRaises(Exception):
            h.redirect_request(req, None, 302, "Found", {}, "http://a.example/")


class KevReflag(Run):
    def test_seen_dep_reported_again_when_it_joins_kev(self):
        kev_cves = KEV["vulnerabilities"]
        KEV["vulnerabilities"] = [v for v in kev_cves if v["cveID"] != "CVE-2026-0001"]
        try:
            new, _, state, _ = s.run(self.settings, {}, NOW)
            self.assertEqual(new["deps"][0]["kev"], [])
        finally:
            KEV["vulnerabilities"] = kev_cves
        new2, _, state2, _ = s.run(self.settings, state, NOW)
        self.assertEqual([d["kev"] for d in new2["deps"]], [["CVE-2026-0001"]])
        new3, _, _, _ = s.run(self.settings, state2, NOW)
        self.assertEqual(new3["deps"], [])


if __name__ == "__main__":
    unittest.main()
