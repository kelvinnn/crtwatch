"""Made-up demo data: a fictional company, "Acme", with the kinds of mistakes crtwatch is built to find.
Loaded with `crtwatch --db demo.db demo`. Nothing here touches the network."""
import json

from . import db, scan

DOMAINS = ["acme-example.com", "acme-ops-example.io"]

# (project, exposure group, patterns)
PROJECTS = [
    ("Storefront", "retail", ["shop.acme-example.com", "*.shop.acme-example.com"]),
    ("Brand site", "retail", ["acme-example.com", "www.acme-example.com", "blog.acme-example.com"]),
    ("Payroll", "internal", ["payroll.acme-example.com", "*.payroll.acme-example.com"]),
    ("HR Portal", "internal", ["hr.acme-example.com"]),
    ("Ops Admin", "ops", ["admin.acme-ops-example.io", "grafana.acme-ops-example.io"]),
    ("Partner API", "partners", ["partners.acme-ops-example.io", "*.partners.acme-ops-example.io"]),
]


def _cert(key, names, nb="2025-03-01T00:00:00", na="2026-12-01T00:00:00", issuer="C=US, O=Let's Encrypt, CN=R11"):
    return {"key": f"demo:{key}", "source": "demo", "crtsh_id": None, "issuer": issuer, "common_name": names[0],
            "not_before": nb, "not_after": na, "sans": sorted(names)}


CERTS = [
    _cert(1, ["shop.acme-example.com", "www.shop.acme-example.com"]),
    _cert(2, ["api.shop.acme-example.com"]),
    _cert(3, ["acme-example.com", "www.acme-example.com"]),
    _cert(4, ["blog.acme-example.com", "blog.acme-legacy-example.net"], nb="2022-05-01T00:00:00", na="2022-08-01T00:00:00"),
    _cert(5, ["payroll.acme-example.com", "staging.payroll.acme-example.com"]),
    _cert(6, ["hr.acme-example.com", "payroll.acme-example.com"], nb="2023-01-10T00:00:00", na="2023-04-10T00:00:00"),
    # The mistake: one old certificate covering payroll *and* the ops admin panel on the other domain.
    _cert(7, ["admin.acme-ops-example.io", "payroll.acme-example.com"], nb="2021-06-01T00:00:00", na="2021-09-01T00:00:00"),
    _cert(8, ["admin.acme-ops-example.io", "grafana.acme-ops-example.io"]),
    _cert(9, ["partners.acme-ops-example.io", "v2.partners.acme-ops-example.io"]),
    _cert(10, ["old-crm.acme-example.com"], nb="2020-02-01T00:00:00", na="2020-05-01T00:00:00"),
    _cert(11, ["vpn.acme-ops-example.io"]),
    _cert(12, ["status.acme-example.com"]),
]

DNS = {
    "shop.acme-example.com": ("live", "203.0.113.10"),
    "www.shop.acme-example.com": ("live", "203.0.113.10"),
    "api.shop.acme-example.com": ("live", "203.0.113.11"),
    "acme-example.com": ("live", "203.0.113.20"),
    "www.acme-example.com": ("live", "203.0.113.20"),
    "blog.acme-example.com": ("nxdomain", None),
    "payroll.acme-example.com": ("live", "198.51.100.5"),
    "staging.payroll.acme-example.com": ("live", "198.51.100.6"),
    "hr.acme-example.com": ("live", "198.51.100.7"),
    "admin.acme-ops-example.io": ("live", "192.0.2.40"),
    "grafana.acme-ops-example.io": ("live", "192.0.2.41"),
    "partners.acme-ops-example.io": ("live", "192.0.2.50"),
    "v2.partners.acme-ops-example.io": ("live", "192.0.2.51"),
    "old-crm.acme-example.com": ("dangling", "CNAME -> acme-crm.hosted-app-example.net (NXDOMAIN)"),
    "vpn.acme-ops-example.io": ("live", "192.0.2.60"),
    "status.acme-example.com": ("live", "CNAME status-page-example.net -> 203.0.113.99"),
}


def load():
    """Fill the current database with the demo company. Refuses to touch a database that has data."""
    with db.session() as c:
        if c.execute("SELECT COUNT(*) FROM domains").fetchone()[0]:
            raise SystemExit(f"{db.DB_PATH} already has domains. Use an empty database, e.g. --db demo.db")
        for d in DOMAINS:
            db.add_domain(c, d)
        for name, group, patterns in PROJECTS:
            p = db.add_project(c, name)
            c.execute("UPDATE projects SET exposure_group=? WHERE id=?", (group, p["id"]))
            for pat in patterns:
                db.add_rule(c, p["id"], pat)
        c.execute("UPDATE projects SET planned_domain='acme-people-example.com' WHERE exposure_group='internal'")
        c.execute("INSERT INTO candidates(domain, checked_at, verdict, detail) VALUES (?,?,?,?)",
                  ("acme-people-example.com", db.now(), "clean", json.dumps({
                      "source": "demo", "certs": 0, "names": [], "linked_names": [], "in_inventory": False,
                      "registered": False, "first_cert": None,
                      "notes": ["No certificates have ever been logged for this domain.",
                                "Not registered (NXDOMAIN at the root). You'd need to buy it."]})))
    for d in DOMAINS:
        with db.session() as c:
            dom = c.execute("SELECT * FROM domains WHERE name=?", (d,)).fetchone()
        mine = [x for x in CERTS if any(n == d or n.endswith("." + d) for n in x["sans"])]
        scan._store(d, dom, mine, set(), ["demo"])
        with db.session() as c:
            c.execute("INSERT INTO scans(domain_id, started_at, finished_at, status, sources, hosts_total, new_hosts, new_certs)"
                      " SELECT id, ?, ?, 'ok', '[\"demo\"]', (SELECT COUNT(*) FROM hosts WHERE domain_id=domains.id), 0, 0"
                      " FROM domains WHERE name=?", (db.now(), db.now(), d))
            c.execute("UPDATE domains SET last_scan_at=?, last_scan_status='ok' WHERE name=?", (db.now(), d))
    with db.session() as c:
        c.executemany("UPDATE hosts SET dns_status=?, dns_detail=?, dns_checked_at=? WHERE name=?",
                      [(s, detail, db.now(), h) for h, (s, detail) in DNS.items()])
        db.add_event(c, "new_cert", "acme-ops-example.io", "vpn.acme-ops-example.io",
                     {"sans": ["vpn.acme-ops-example.io"], "issuer": "C=US, O=Let's Encrypt, CN=R11"})
        db.add_event(c, "new_host", "acme-ops-example.io", "vpn.acme-ops-example.io", {"sources": ["demo"]})
        c.execute("UPDATE events SET notified=1")
