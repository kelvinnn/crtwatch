"""Offline tests: fake CT data in, findings / violations / rotation plan out. No network needed.

Run with:  python -m unittest discover -s tests
"""
import os
import tempfile
import unittest
from unittest import mock

import dns.resolver

from crtwatch import analyze, db, scan, separation, sources


def cert(key, *names, not_after="2099-01-01T00:00:00"):
    return {"key": key, "source": "test", "crtsh_id": None, "issuer": "Test CA", "common_name": names[0],
            "not_before": "2024-01-01T00:00:00", "not_after": not_after, "sans": sorted(names)}


# A made-up company. acme.com hosts the retail site and, by mistake, payroll.
# One old cert put payroll next to the ops admin panel on acme-ops.io.
CT = {
    "acme.com": [
        cert("c1", "shop.acme.com", "www.shop.acme.com"),
        cert("c2", "payroll.acme.com"),
        cert("c3", "admin.acme-ops.io", "payroll.acme.com", not_after="2020-01-01T00:00:00"),
        cert("c4", "acme.com", "www.acme.com"),
        cert("c6", "shop.acme.com", "a.cdn-one.com", "b.cdn-two.com", "c.cdn-three.com"),  # shared CDN cert
        cert("c7", "blog.acme.com", "blog.acme-old.net"),
        cert("c8", "legacy.shop.acme.com"),
    ],
    "acme-ops.io": [
        cert("c3", "admin.acme-ops.io", "payroll.acme.com", not_after="2020-01-01T00:00:00"),
        cert("c5", "portal.acme-ops.io"),
    ],
}


def fake_source(domain):
    return CT.get(domain, []), []


class CrtwatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = os.path.join(self.tmp.name, "test.db")
        db.init()
        self.patch = mock.patch.dict(sources.CERT_SOURCES, {"crtsh_pg": fake_source})
        self.patch.start()
        with db.session() as c:
            for d in ("acme.com", "acme-ops.io"):
                db.add_domain(c, d)
            for name, group, rules in [
                ("Shop", "retail", ["shop.acme.com", "*.shop.acme.com"]),
                ("Main", "retail", ["acme.com", "www.acme.com", "blog.acme.com", "legacy.shop.acme.com"]),
                ("Payroll", "internal", ["payroll.acme.com"]),
                ("Admin", "ops", ["admin.acme-ops.io"]),
                ("Portal", "", ["portal.acme-ops.io"]),
            ]:
                p = db.add_project(c, name)
                c.execute("UPDATE projects SET exposure_group=? WHERE id=?", (group, p["id"]))
                for r in rules:
                    db.add_rule(c, p["id"], r)
        for d in ("acme.com", "acme-ops.io"):
            scan.scan_domain(d, cert_chain=["crtsh_pg"], name_sources=[])

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    # --- scanning ---------------------------------------------------------------------------

    def test_scan_stores_hosts_and_baseline_has_no_events(self):
        inv = analyze.Inventory()
        self.assertIn("payroll.acme.com", inv.hosts)
        self.assertEqual(inv.hosts["admin.acme-ops.io"]["domain"], "acme-ops.io")
        self.assertNotIn("blog.acme-old.net", inv.hosts)  # not an inventory domain
        with db.session() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_rescan_reports_new_names(self):
        CT["acme.com"].append(cert("c9", "secret.acme.com"))
        try:
            r = scan.scan_domain("acme.com", cert_chain=["crtsh_pg"], name_sources=[])
        finally:
            CT["acme.com"].pop()
        self.assertEqual(r["new_hosts"], 1)
        with db.session() as c:
            kinds = [e["kind"] for e in c.execute("SELECT kind FROM events")]
        self.assertIn("new_host", kinds)
        self.assertIn("new_cert", kinds)

    def test_failed_sources_mark_scan_failed(self):
        def boom(_):
            raise sources.SourceError("down")
        with mock.patch.dict(sources.CERT_SOURCES, {"crtsh_pg": boom}):
            with self.assertRaises(sources.SourceError):
                scan.scan_domain("acme.com", cert_chain=["crtsh_pg"], name_sources=[])
        with db.session() as c:
            self.assertEqual(c.execute("SELECT status FROM scans ORDER BY id DESC LIMIT 1").fetchone()[0], "failed")
            self.assertEqual(db.running_scans(c), [])

    # --- mapping and findings ---------------------------------------------------------------

    def test_most_specific_rule_wins(self):
        inv = analyze.Inventory()
        name = lambda h: inv.project_name(inv.hosts[h]["project_id"])
        self.assertEqual(name("www.shop.acme.com"), "Shop")       # glob
        self.assertEqual(name("legacy.shop.acme.com"), "Main")    # exact beats *.shop.acme.com

    def test_findings(self):
        inv = analyze.Inventory()
        fs = analyze.findings(inv)
        kinds = {(f["kind"], f.get("root")) for f in fs}
        self.assertIn(("shared_root", "acme.com"), kinds)
        links = [f for f in fs if f["kind"] == "cert_link" and set(f["projects"]) == {"Admin", "Payroll"}]
        self.assertEqual(links[0]["severity"], "critical")        # crosses two root domains
        self.assertEqual(links[0]["active_certs"], 0)              # the linking cert has expired
        foreign = {f["root"] for f in fs if f["kind"] == "foreign_root"}
        self.assertIn("acme-old.net", foreign)
        self.assertNotIn("cdn-one.com", foreign)                   # shared CDN cert is ignored

    def test_blast_radius_follows_root_then_cert(self):
        inv = analyze.Inventory()
        br = analyze.blast_radius(inv, next(p for p, v in inv.projects.items() if v["name"] == "Shop"))
        self.assertIn("Payroll", br["exposes"])
        self.assertEqual(br["exposes"]["Admin"]["hops"], 2)       # acme.com search, then the shared cert

    # --- separation and rotation ------------------------------------------------------------

    def test_violations(self):
        v = {(x["a"], x["b"]) if x["a"] < x["b"] else (x["b"], x["a"]): x for x in separation.violations(analyze.Inventory())}
        self.assertEqual(v[("Payroll", "Shop")]["cause"], "same root domain")
        self.assertEqual(v[("Admin", "Payroll")]["cause"], "same certificate")
        self.assertEqual(v[("Admin", "Shop")]["cause"], "indirect")
        self.assertNotIn(("Main", "Shop"), v)                      # same group
        self.assertFalse(any("Portal" in k for k in v))           # no group = not checked
        path = v[("Admin", "Shop")]["path"]
        self.assertGreaterEqual(len(path), 2)

    def test_pair_rule(self):
        inv = analyze.Inventory()
        ids = {p["name"]: pid for pid, p in inv.projects.items()}
        with db.session() as c:
            db.add_separation(c, ids["Portal"], ids["Admin"])
        v = separation.violations(analyze.Inventory())
        self.assertTrue(any({x["a"], x["b"]} == {"Portal", "Admin"} and x["rule"] == "pair rule" for x in v))

    def test_rotation_plan(self):
        plan = separation.rotation_plan(analyze.Inventory())
        roots = {r["root"]: r for r in plan["roots"]}
        self.assertEqual(roots["acme.com"]["keep"], "group retail")  # holds the apex
        self.assertEqual(roots["acme.com"]["moves"], ["group internal"])
        self.assertNotIn("acme-ops.io", roots)                       # ops + ungrouped Portal don't conflict
        move = plan["moves"][0]
        self.assertEqual(move["burned"][0]["names"], ["payroll.acme.com"])
        self.assertEqual(plan["remaining"], [])                      # moving payroll resolves everything

    def test_keep_group_override(self):
        with db.session() as c:
            c.execute("UPDATE domains SET keep_group='internal' WHERE name='acme.com'")
        plan = separation.rotation_plan(analyze.Inventory())
        root = next(r for r in plan["roots"] if r["root"] == "acme.com")
        self.assertEqual(root["keep"], "group internal")
        self.assertEqual(root["moves"], ["group retail"])

    def test_planned_domain_next_to_conflict_is_flagged(self):
        with db.session() as c:
            c.execute("UPDATE projects SET planned_domain='acme-ops.io' WHERE exposure_group='internal'")
        move = separation.rotation_plan(analyze.Inventory())["moves"][0]
        self.assertFalse(move["checks"][0]["ok"])
        self.assertTrue(any("already hosts group ops" in i for i in move["checks"][0]["issues"]))

    def test_candidate_check(self):
        CT["fresh-start.dev"] = []
        CT["used-before.dev"] = [cert("x1", "used-before.dev", "www.acme.com")]
        try:
            with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
                clean = separation.check_candidate("fresh-start.dev")
                linked = separation.check_candidate("used-before.dev")
        finally:
            del CT["fresh-start.dev"], CT["used-before.dev"]
        self.assertEqual(clean["verdict"], "clean")
        self.assertFalse(clean["registered"])
        self.assertEqual(linked["verdict"], "linked")
        self.assertEqual(linked["linked_names"], ["www.acme.com"])


class DemoTest(unittest.TestCase):
    def test_demo_loads_and_shows_problems(self):
        from crtwatch import demo
        with tempfile.TemporaryDirectory() as tmp:
            db.DB_PATH = os.path.join(tmp, "demo.db")
            db.init()
            demo.load()
            inv = analyze.Inventory()
            self.assertEqual(len(inv.domains), 2)
            self.assertTrue(separation.violations(inv))
            self.assertTrue(any(f["kind"] == "dangling_cname" for f in analyze.findings(inv)))
            with self.assertRaises(SystemExit):  # never overwrites a database that has data
                demo.load()


if __name__ == "__main__":
    unittest.main()
