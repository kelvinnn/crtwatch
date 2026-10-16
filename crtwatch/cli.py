"""crtwatch command line. Run `python -m crtwatch -h`."""
import argparse
import csv
import json
import logging
import os
import sys
import time

from . import __version__, analyze, db, dnscheck, scan, separation

SEV_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def parse_interval(s):
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    s = s.strip().lower()
    if s[-1] in units:
        return int(float(s[:-1]) * units[s[-1]])
    return int(s)


def _read_list(path):
    with open(path) as f:
        return [ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()]


def cmd_domain(a):
    with db.session() as c:
        if a.action == "add":
            names = list(a.names) + (_read_list(a.file) if a.file else [])
            for n in names:
                d = db.add_domain(c, n, a.notes or "")
                print("added", d["name"])
        elif a.action == "rm":
            for n in a.names:
                c.execute("DELETE FROM domains WHERE name=?", (db.normalize_domain(n),))
                print("removed", n)
        elif a.action in ("enable", "disable"):
            for n in a.names:
                c.execute("UPDATE domains SET enabled=? WHERE name=?", (a.action == "enable", db.normalize_domain(n)))
        else:
            rows = c.execute("SELECT d.*, (SELECT COUNT(*) FROM hosts h WHERE h.domain_id=d.id) n FROM domains d ORDER BY name")
            for r in rows:
                flag = "" if r["enabled"] else " (disabled)"
                print(f"{r['name']:40} {r['n']:6} hosts  last scan {r['last_scan_at'] or 'never'} {r['last_scan_status'] or ''}{flag}")


def cmd_project(a):
    with db.session() as c:
        if a.action == "add":
            p = db.add_project(c, a.name, a.notes or "")
            for pat in a.rule or []:
                db.add_rule(c, p["id"], pat)
            print("project", p["name"])
        elif a.action == "rm":
            c.execute("DELETE FROM projects WHERE name=?", (a.name,))
        else:
            for p in c.execute("SELECT * FROM projects ORDER BY name"):
                pats = [r["pattern"] for r in c.execute("SELECT pattern FROM rules WHERE project_id=? ORDER BY pattern", (p["id"],))]
                extra = (f"  [group {p['exposure_group']}]" if p["exposure_group"] else "") + (
                    f"  -> {p['planned_domain']}" if p["planned_domain"] else "")
                print(f"{p['name']}{extra}: {', '.join(pats) or '(no rules)'}")


def cmd_rule(a):
    with db.session() as c:
        p = c.execute("SELECT * FROM projects WHERE name=?", (a.project,)).fetchone()
        if not p:
            if a.action == "rm":
                sys.exit(f"no project {a.project}")
            p = db.add_project(c, a.project)
        for pat in a.patterns:
            if a.action == "add":
                db.add_rule(c, p["id"], pat)
            else:
                c.execute("DELETE FROM rules WHERE project_id=? AND pattern=?", (p["id"], pat.lower()))


def cmd_import(a):
    """CSV with header: project,pattern  (optional columns: group, domain)."""
    n = 0
    with open(a.file, newline="") as f, db.session() as c:
        for row in csv.DictReader(f):
            row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
            if row.get("domain"):
                db.add_domain(c, row["domain"])
            if row.get("project") and row.get("pattern"):
                p = db.add_project(c, row["project"])
                db.add_rule(c, p["id"], row["pattern"])
                n += 1
            if row.get("project") and row.get("group"):
                p = db.add_project(c, row["project"])
                c.execute("UPDATE projects SET exposure_group=? WHERE id=?", (row["group"], p["id"]))
    print(f"imported {n} rules")


def cmd_scan(a):
    names = [db.normalize_domain(n) for n in a.domains] or scan.enabled_domains()
    if not names:
        sys.exit("no domains. add some with: crtwatch domain add example.com")
    with db.session() as c:
        for n in names:
            db.add_domain(c, n)
    results = scan.scan_many(names, workers=a.workers, every_cert_source=a.every_source)
    for r in results:
        if r["status"] == "failed":
            print(f"FAIL {r['domain']}: {r.get('error')}")
        else:
            errs = f"  errors: {', '.join(r['errors'])}" if r.get("errors") else ""
            base = " (baseline)" if r.get("baseline") else ""
            print(f"{r['status']:7} {r['domain']:35} {r['hosts_total']:6} hosts  +{r['new_hosts']} new hosts  "
                  f"+{r['new_certs']} new certs  via {','.join(r['sources'])}{base}{errs}")
    if a.dns:
        print("dns:", dnscheck.check_hosts())


def cmd_dns(a):
    names = None
    if a.domains:
        with db.session() as c:
            q = "SELECT h.name FROM hosts h JOIN domains d ON d.id=h.domain_id WHERE d.name IN (%s)" % ",".join("?" * len(a.domains))
            names = [r["name"] for r in c.execute(q, [db.normalize_domain(d) for d in a.domains])]
    print(dnscheck.check_hosts(names))


def cmd_report(a):
    s = analyze.summary()
    if a.json:
        print(json.dumps(s, indent=2, default=str))
        return
    order = list(analyze.SEV_ORDER)
    floor = order.index(a.min_severity)
    c = s["counts"]
    print(f"{c['domains']} domains, {c['projects']} projects, {c['hosts']} hosts ({c['unassigned']} unassigned), {c['certs']} certs\n")
    for f in s["findings"]:
        if order.index(f["severity"]) > floor:
            continue
        print(f"[{SEV_MARK[f['severity']]}] {f['title']}")
        print(f"       {f['detail']}")
        if f.get("projects") and isinstance(f["projects"], dict):
            for p, hs in f["projects"].items():
                more = f" (+{f['counts'][p] - len(hs[:5])} more)" if f["counts"][p] > 5 else ""
                print(f"       - {p}: {', '.join(hs[:5])}{more}")
        elif f.get("hosts"):
            print(f"       hosts: {', '.join(f['hosts'][:8])}{' …' if len(f['hosts']) > 8 else ''}")
        if f.get("example_cert"):
            print(f"       {f['certs']} cert(s), {f['active_certs']} still valid, e.g. {f['example_cert']}")
        print()


def cmd_exposure(a):
    s = analyze.summary()
    for r in s["blast_radius"]:
        if a.project and r["project"] != a.project:
            continue
        print(f"{r['project']}  ({r['own_hosts']} hosts) -> attacker reaches {r['reachable_hosts']} other hosts")
        if not r["exposes"]:
            print("    isolated: nothing else reachable via root or certificate pivots")
        for name, e in r["exposes"].items():
            print(f"    {name:30} {e['hosts']:5} hosts  in {e['hops']} hop(s)  e.g. {e['example']}  via {e['how']}")
        print()


def cmd_hosts(a):
    inv = analyze.Inventory()
    rows = analyze.host_rows(inv, domain=a.domain, project="(unassigned)" if a.unassigned else a.project, q=a.q)
    if a.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["name", "root", "project", "rule", "certs", "active_cert", "first_seen", "dns_status", "dns_detail", "ignored"])
        for r in rows:
            w.writerow([r["name"], r["root"], r["project"] or "", r["rule"] or "", r["certs"], r["active_cert"],
                        r["first_seen"], r["dns_status"] or "", r["dns_detail"] or "", r["ignored"]])
        return
    for r in rows:
        print(f"{r['name']:55} {r['project'] or '-':20} certs={r['certs']:<4} {'valid' if r['active_cert'] else 'expired':7} "
              f"{r['dns_status'] or ''}{' (ignored)' if r['ignored'] else ''}")


def cmd_assign(a):
    with db.session() as c:
        p = db.add_project(c, a.project)
        for h in a.hosts:
            db.add_rule(c, p["id"], h)


def cmd_ignore(a):
    with db.session() as c:
        for h in a.hosts:
            c.execute("UPDATE hosts SET ignored=? WHERE name=?", (0 if a.undo else 1, h.lower()))


def cmd_events(a):
    with db.session() as c:
        for e in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (a.limit,)):
            print(f"{e['ts']}  {e['kind']:9} {e['domain'] or '':30} {e['subject']}")


def _project(c, name):
    p = c.execute("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    if not p:
        sys.exit(f"no project named {name!r} (see: crtwatch project list)")
    return p


def cmd_group(a):
    with db.session() as c:
        if a.clear:
            for name in [a.group] + a.projects:
                c.execute("UPDATE projects SET exposure_group='' WHERE id=?", (_project(c, name)["id"],))
            return
        if not a.projects:
            for g, names in _groups(c).items():
                print(f"{g or '(no group)'}: {', '.join(names)}")
            return
        for name in a.projects:
            c.execute("UPDATE projects SET exposure_group=? WHERE id=?", (a.group, _project(c, name)["id"]))
        print(f"group {a.group}: {', '.join(a.projects)}")


def _groups(c):
    out = {}
    for p in c.execute("SELECT name, exposure_group FROM projects ORDER BY exposure_group, name"):
        out.setdefault(p["exposure_group"], []).append(p["name"])
    return out


def cmd_apart(a):
    with db.session() as c:
        pa, pb = _project(c, a.a), _project(c, a.b)
        if a.rm:
            x, y = sorted((pa["id"], pb["id"]))
            c.execute("DELETE FROM separations WHERE project_a=? AND project_b=?", (x, y))
        else:
            db.add_separation(c, pa["id"], pb["id"])
            print(f"{a.a} and {a.b} must never be seen together")


def cmd_keep(a):
    with db.session() as c:
        c.execute("UPDATE domains SET keep_group=? WHERE name=?", (a.group or "", db.normalize_domain(a.domain)))


def cmd_target(a):
    with db.session() as c:
        dom = db.normalize_domain(a.domain) if a.domain != "-" else ""
        if a.group:
            n = c.execute("UPDATE projects SET planned_domain=? WHERE exposure_group=?", (dom, a.name)).rowcount
            print(f"{n} project(s) in group {a.name} planned for {dom or '(none)'}")
        else:
            c.execute("UPDATE projects SET planned_domain=? WHERE id=?", (dom, _project(c, a.name)["id"]))


def cmd_check(a):
    v = separation.violations(analyze.Inventory())
    if a.json:
        print(json.dumps(v, indent=2))
        return
    if not v:
        print("No separation violations. (Projects without an exposure group or pair rule aren't checked.)")
        return
    print(f"{len(v)} pair(s) of projects can be seen together but shouldn't be:\n")
    for x in v:
        extra = f" on {', '.join(x['shared_roots'])}" if x["shared_roots"] else ""
        if x["shared_certs"]:
            extra += f"; {x['shared_certs']} shared cert(s), {x['active_shared_certs']} still valid"
        print(f"  {x['a']}  <->  {x['b']}   [{x['rule']}]  {x['cause']}{extra}")
        for st in x["path"]:
            print(f"      {st['from']}  --{st['how']}-->  {st['to']}")
        print()


def cmd_plan(a):
    inv = analyze.Inventory()
    plan = separation.rotation_plan(inv)
    if a.json:
        print(json.dumps(plan, indent=2, default=list))
        return
    if not plan["roots"] and not plan["remaining"]:
        print("Nothing to rotate: no root domain holds projects that must stay apart.")
        return
    for r in plan["roots"]:
        print(f"{r['root']}: keep {r['keep']} ({r['keep_reason']}); move {', '.join(r['moves'])}")
        if len(r["stays"]) > 1:
            print(f"    also staying: {', '.join(s for s in r['stays'] if s != r['keep'])}")
    print()
    for m in plan["moves"]:
        print(f"MOVE {m['unit']}  ({', '.join(m['projects'])})")
        for lv in m["leaving"]:
            live = (f", {len(lv['live'])} still live: {', '.join(lv['live'][:6])}{' …' if len(lv['live']) > 6 else ''}"
                    if lv["dns_checked"] else ", DNS not checked yet (run: crtwatch dns)")
            print(f"    off {lv['root']}: {lv['hosts']} hostname(s){live}")
        for b in m["burned"]:
            print(f"    burned names: {b['certs']} old cert(s) show {', '.join(b['names'][:5])} next to {b['with']}. "
                  "Don't reuse these names.")
        if not m["planned_domains"]:
            print(f"    new domain: not chosen yet (crtwatch target {'--group ' if m['unit'].startswith('group ') else ''}"
                  f"'{m['unit'].removeprefix('group ')}' newdomain.com)")
        for ch in m["checks"]:
            status = "OK" if ch["ok"] else "; ".join(ch["issues"])
            print(f"    new domain {ch['domain']} [{ch['verdict']}]: {status}")
        print()
    if plan["remaining"]:
        print("Still linked after these moves:")
        for v in plan["remaining"]:
            print(f"  {v['a']} <-> {v['b']} ({v['cause']}): {v['fix']}")
        print()
    print("Checklist for each rotation:")
    for i, item in enumerate(separation.ROTATION_CHECKLIST, 1):
        print(f"  {i}. {item}")


def cmd_candidate(a):
    for d in a.domains:
        r = separation.check_candidate(d)
        print(f"{r['domain']}: {r['verdict'].upper()}  ({r['certs']} cert(s) in CT, registered={r['registered']})")
        for n in r["notes"]:
            print(f"    {n}")
        if r["linked_names"]:
            print(f"    linked names: {', '.join(r['linked_names'][:10])}")


def cmd_monitor(a):
    every = parse_interval(a.every)
    logging.info("monitoring every %ss", every)
    while True:
        names = scan.enabled_domains()
        for r in scan.scan_many(names, workers=a.workers):
            logging.info("%s %s +%s hosts +%s certs", r["domain"], r["status"], r.get("new_hosts"), r.get("new_certs"))
        if a.dns:
            logging.info("dns %s", dnscheck.check_hosts())
        time.sleep(every)


def cmd_demo(a):
    from . import demo
    demo.load()
    print(f"Loaded the demo company into {db.DB_PATH}")
    print(f"Now run:  crtwatch --db {db.DB_PATH} serve")


def cmd_serve(a):
    import uvicorn
    if a.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("CRTWATCH_PASSWORD") \
            and os.environ.get("CRTWATCH_ALLOW_NO_AUTH") != "1":
        sys.exit("refusing to listen on a public interface without CRTWATCH_PASSWORD set "
                 "(the inventory is a map of your attack surface). Set CRTWATCH_ALLOW_NO_AUTH=1 to override.")
    from . import web
    web.SCAN_EVERY = parse_interval(a.every) if a.every else None
    uvicorn.run(web.app, host=a.host, port=a.port, log_level="info")


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    ap = argparse.ArgumentParser(prog="crtwatch", description="Map your domains' CT exposure to projects.")
    ap.add_argument("--db", help=f"database file (default: $CRTWATCH_DB or ./data/crtwatch.db, now {db.DB_PATH})")
    ap.add_argument("--version", action="version", version=f"crtwatch {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("domain", help="manage inventory domains")
    p.add_argument("action", choices=["add", "rm", "list", "enable", "disable"])
    p.add_argument("names", nargs="*")
    p.add_argument("-f", "--file", help="file with one domain per line")
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_domain)

    p = sub.add_parser("project", help="manage projects")
    p.add_argument("action", choices=["add", "rm", "list"])
    p.add_argument("name", nargs="?")
    p.add_argument("--rule", action="append", help="hostname glob, repeatable: --rule 'shop.acme.com' --rule '*.shop.acme.com'")
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_project)

    p = sub.add_parser("rule", help="add/remove hostname patterns for a project")
    p.add_argument("action", choices=["add", "rm"])
    p.add_argument("project")
    p.add_argument("patterns", nargs="+")
    p.set_defaults(fn=cmd_rule)

    p = sub.add_parser("import", help="import a CSV with columns project,pattern[,group][,domain]")
    p.add_argument("file")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("scan", help="pull CT data (all enabled domains if none given)")
    p.add_argument("domains", nargs="*")
    p.add_argument("--dns", action="store_true", help="resolve every host afterwards")
    p.add_argument("--every-source", action="store_true", help="run all cert sources instead of stopping at the first that works")
    p.add_argument("--workers", type=int, default=2)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("dns", help="resolve hosts (live / stale / dangling CNAME)")
    p.add_argument("domains", nargs="*")
    p.set_defaults(fn=cmd_dns)

    p = sub.add_parser("report", help="findings")
    p.add_argument("--json", action="store_true")
    p.add_argument("--min-severity", default="info", choices=list(analyze.SEV_ORDER))
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("exposure", help="per-project blast radius")
    p.add_argument("project", nargs="?")
    p.set_defaults(fn=cmd_exposure)

    p = sub.add_parser("hosts", help="list hosts")
    p.add_argument("--domain")
    p.add_argument("--project")
    p.add_argument("--unassigned", action="store_true")
    p.add_argument("-q")
    p.add_argument("--csv", action="store_true")
    p.set_defaults(fn=cmd_hosts)

    p = sub.add_parser("assign", help="assign exact hostnames to a project")
    p.add_argument("project")
    p.add_argument("hosts", nargs="+")
    p.set_defaults(fn=cmd_assign)

    p = sub.add_parser("ignore", help="hide hosts from findings (e.g. a vendor's name on a shared cert)")
    p.add_argument("hosts", nargs="+")
    p.add_argument("--undo", action="store_true")
    p.set_defaults(fn=cmd_ignore)

    p = sub.add_parser("events", help="recent new hosts / certs")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(fn=cmd_events)

    p = sub.add_parser("group", help="put projects in an exposure group (same group = may be seen together)")
    p.add_argument("group", nargs="?", default="")
    p.add_argument("projects", nargs="*")
    p.add_argument("--clear", action="store_true", help="remove the listed projects from their group")
    p.set_defaults(fn=cmd_group)

    p = sub.add_parser("apart", help="two projects must never be seen together")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--rm", action="store_true")
    p.set_defaults(fn=cmd_apart)

    p = sub.add_parser("keep", help="which exposure group stays on a domain when it gets split")
    p.add_argument("domain")
    p.add_argument("group", nargs="?")
    p.set_defaults(fn=cmd_keep)

    p = sub.add_parser("target", help="record the domain a project (or --group) will rotate to; '-' clears")
    p.add_argument("name")
    p.add_argument("domain")
    p.add_argument("--group", action="store_true", help="name is an exposure group")
    p.set_defaults(fn=cmd_target)

    p = sub.add_parser("check", help="which projects that must stay apart can be seen together")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("plan", help="domain rotation plan to separate them")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("candidate", help="vet a domain before rotating a project to it")
    p.add_argument("domains", nargs="+")
    p.set_defaults(fn=cmd_candidate)

    p = sub.add_parser("monitor", help="rescan forever on an interval")
    p.add_argument("--every", default="6h")
    p.add_argument("--dns", action="store_true")
    p.add_argument("--workers", type=int, default=2)
    p.set_defaults(fn=cmd_monitor)

    p = sub.add_parser("demo", help="load a made-up company into an empty database, to try crtwatch without scanning")
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("serve", help="web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--every", help="also rescan in the background, e.g. 6h")
    p.set_defaults(fn=cmd_serve)

    a = ap.parse_args(argv)
    if a.db:
        db.DB_PATH = os.path.abspath(a.db)
    db.init()
    if a.cmd == "project" and a.action in ("add", "rm") and not a.name:
        ap.error("project name required")
    a.fn(a)
