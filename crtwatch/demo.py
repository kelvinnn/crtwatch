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


def _page(title, body, color="#1d4ed8"):
    return (f"<!doctype html><html><head><title>{title}</title><style>body{{font:16px system-ui;margin:0;color:#111}}"
            f"header{{background:{color};color:#fff;padding:18px 28px;font-weight:600}}main{{padding:28px;max-width:640px}}"
            f"input,button{{font:inherit;padding:8px 10px;margin:4px 0;display:block}}button{{background:{color};color:#fff;border:0;border-radius:4px}}"
            f"</style></head><body><header>{title}</header><main>{body}</main></body></html>")


# host: (scheme, status, reason, title, content type, server, redirect target, tls error, body or error)
PROBES = {
    "shop.acme-example.com": ("https", 200, "OK", "Acme Shop: everything for your workshop", "text/html", "nginx", None, None,
                              _page("Acme Shop: everything for your workshop", "<h1>Spring sale</h1><p>Up to 30% off hand tools and workbenches. Free delivery over $50.</p><p><a href='#'>Browse the catalogue</a></p>")),
    "www.shop.acme-example.com": ("https", 301, "Moved Permanently", None, "text/html", "nginx", "https://shop.acme-example.com/", None, None),
    "api.shop.acme-example.com": ("https", 200, "OK", None, "application/json", "envoy", None, None, '{"status": "ok", "service": "catalog-api", "version": "3.2.1"}'),
    "acme-example.com": ("https", 200, "OK", "Acme | Tools that last", "text/html", "cloudflare", None, None,
                         _page("Acme | Tools that last", "<h1>Built to last since 1952</h1><p>Family-owned maker of hand tools.</p>", "#0f766e")),
    "www.acme-example.com": ("https", 301, "Moved Permanently", None, "text/html", "cloudflare", "https://acme-example.com/", None, None),
    "payroll.acme-example.com": ("https", 200, "OK", "Acme Payroll - Sign in", "text/html", "Microsoft-IIS/10.0", None, None,
                                 _page("Acme Payroll - Sign in", "<h2>Employee sign-in</h2><input placeholder='Employee ID'><input type='password' placeholder='Password'><button>Sign in</button>", "#7c3aed")),
    "staging.payroll.acme-example.com": ("https", 503, "Service Unavailable", "503 Service Unavailable", "text/html", "nginx", None, None,
                                         "<html><head><title>503 Service Unavailable</title></head><body><h1>503 Service Unavailable</h1></body></html>"),
    # The mistake the redirect check catches: HR already points at the domain it's supposed to move to in secret.
    "hr.acme-example.com": ("https", 302, "Found", None, "text/html", "nginx", "https://hr.acme-people-example.com/", None, None),
    "admin.acme-ops-example.io": ("https", 401, "Unauthorized", "401 Authorization Required", "text/html", "nginx", None, None,
                                  "<html><head><title>401 Authorization Required</title></head><body><center><h1>401 Authorization Required</h1></center></body></html>"),
    "grafana.acme-ops-example.io": ("https", 200, "OK", "Grafana", "text/html", None, None, "self-signed certificate",
                                    _page("Grafana", "<h2>Welcome to Grafana</h2><input placeholder='email or username'><input type='password' placeholder='password'><button>Log in</button>", "#f46800")),
    "partners.acme-ops-example.io": ("https", 403, "Forbidden", "Attention Required!", "text/html", "cloudflare", None, None,
                                     "<html><head><title>Attention Required!</title></head><body><h1>Sorry, you have been blocked</h1></body></html>"),
    "v2.partners.acme-ops-example.io": ("https", 200, "OK", None, "application/json", "envoy", None, None, '{"error": "missing api key", "docs": "/v2/docs"}'),
    "status.acme-example.com": ("https", 200, "OK", "Acme Status", "text/html", "cloudflare", None, None,
                                _page("Acme Status", "<h2>All systems operational</h2><p>Shop · Payments · Delivery tracking</p>", "#16a34a")),
    "vpn.acme-ops-example.io": (None, None, None, None, None, None, None, None, "timeout"),
    "old-crm.acme-example.com": (None, None, None, None, None, None, None, None, "DNS: nodename nor servname provided, or not known"),
}


def _store_probes(c):
    from .probe import summarize
    for host, (scheme, status, reason, title, ctype, server, target, tls, body) in PROBES.items():
        url = f"https://{host}/"
        if status is None:
            c.execute("INSERT OR REPLACE INTO probes(host, checked_at, scheme, error) VALUES (?,?,?,?)",
                      (host, db.now(), "https", body))
            continue
        redirects = [{"status": status, "from": url, "to": target}] if target else []
        final = target or url
        _, snippet, page = summarize(body.encode(), ctype) if body else (None, None, None)
        c.execute(
            "INSERT OR REPLACE INTO probes(host, checked_at, scheme, url, final_url, status, final_status, reason, title,"
            " content_type, server, length, redirects, tls_error, snippet, html, error)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (host, db.now(), scheme, url, final, status, 200 if target else status, reason, title, ctype,
             server, len(body or ""), json.dumps(redirects), tls, snippet, page if status == 200 else None))


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
        _store_probes(c)
        c.execute("UPDATE events SET notified=1")
