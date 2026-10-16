"""Which projects must not be seen together, where they are, and how to split them up.

Two ways to say "keep apart":
  exposure groups   every project gets a group label. Same group = allowed to be seen together.
                    Projects in different groups must not be reachable from each other.
                    Projects with no group are unconstrained (unless a pair rule names them).
  pair rules        "project A must never be seen with project B", for one-off cases.

A unit is what moves as a whole: a whole exposure group, or a single ungrouped project.
"""
import copy
import json
from collections import defaultdict

import dns.resolver

from . import analyze, db, sources
from .analyze import root_of, trace, walk


def _unit(inv, pid):
    g = (inv.projects.get(pid) or {}).get("exposure_group") or ""
    return ("group", g) if g else ("project", pid)


def unit_label(inv, u):
    return f"group {u[1]}" if u[0] == "group" else inv.project_name(u[1])


def unit_projects(inv, u):
    if u[0] == "group":
        return sorted(pid for pid, p in inv.projects.items() if p.get("exposure_group") == u[1])
    return [u[1]]


def must_separate(inv, p, q):
    if p == q or p is None or q is None:
        return False
    if frozenset((p, q)) in inv.separations:
        return True
    gp, gq = inv.projects[p].get("exposure_group"), inv.projects[q].get("exposure_group")
    return bool(gp and gq and gp != gq)


def units_conflict(inv, a, b):
    return a != b and any(must_separate(inv, p, q) for p in unit_projects(inv, a) for q in unit_projects(inv, b))


def constrained(inv, pid):
    return bool(inv.projects[pid].get("exposure_group")) or any(pid in s for s in inv.separations)


# --- violations --------------------------------------------------------------------------------

def violations(inv):
    out = {}
    for pid in inv.projects:
        if not constrained(inv, pid):
            continue
        seen, _, _ = walk(inv, pid)
        first = {}
        for name, (hop, _, _) in seen.items():
            q = inv.hosts[name]["project_id"]
            if q is not None and q != pid and (q not in first or hop < first[q][0]):
                first[q] = (hop, name)
        for q, (hop, name) in first.items():
            if not must_separate(inv, pid, q):
                continue
            key = frozenset((pid, q))
            if key in out and out[key]["hops"] <= hop:
                continue
            out[key] = {"a": pid, "b": q, "hops": hop, "path": trace(seen, name)}

    result = []
    for v in out.values():
        a, b = v["a"], v["b"]
        ha = [h for h in inv.visible_hosts() if h["project_id"] == a]
        hb = [h for h in inv.visible_hosts() if h["project_id"] == b]
        shared_roots = sorted({h["root"] for h in ha} & {h["root"] for h in hb})
        certs_a = set().union(*(inv.host_certs.get(h["name"], set()) for h in ha)) if ha else set()
        certs_b = set().union(*(inv.host_certs.get(h["name"], set()) for h in hb)) if hb else set()
        shared_certs = certs_a & certs_b
        names_a, names_b = {h["name"] for h in ha}, {h["name"] for h in hb}
        redirect = any(t in names_b for n in names_a for t in inv.redirect_targets.get(n, ())) or \
            any(t in names_a for n in names_b for t in inv.redirect_targets.get(n, ()))
        if shared_roots:
            cause = "same root domain"
        elif shared_certs:
            cause = "same certificate"
        elif redirect:
            cause = "redirect"
        else:
            cause = "indirect"
        pa, pb = inv.projects[a], inv.projects[b]
        if frozenset((a, b)) in inv.separations:
            rule = "pair rule"
        else:
            rule = f"groups {pa['exposure_group']} vs {pb['exposure_group']}"
        result.append({
            "a": pa["name"], "b": pb["name"], "rule": rule, "cause": cause, "hops": v["hops"],
            "shared_roots": shared_roots, "shared_certs": len(shared_certs),
            "active_shared_certs": sum(1 for k in shared_certs if inv.certs.get(k, {}).get("active")),
            "path": v["path"],
        })
    order = {"same root domain": 0, "same certificate": 1, "redirect": 2, "indirect": 3}
    return sorted(result, key=lambda r: (order[r["cause"]], r["hops"], r["a"], r["b"]))


# --- rotation plan -----------------------------------------------------------------------------

def _keeper(inv, root, units):
    """Which unit stays on a root: the domain's keep_group if set, else whoever holds the apex/www,
    else the unit with the most hosts there."""
    for d in inv.domains:
        if root_of(d["name"]) == root and d.get("keep_group"):
            u = ("group", d["keep_group"])
            if u in units:
                return u, "set as this domain's keep group"
    for u, info in units.items():
        if root in info["hosts"] or f"www.{root}" in info["hosts"]:
            return u, "holds the main site (apex or www)"
    u = max(units, key=lambda x: len(units[x]["hosts"]))
    return u, "has the most hosts here"


def rotation_plan(inv):
    per_root = defaultdict(dict)
    for h in inv.visible_hosts():
        if h["project_id"] is None:
            continue
        u = _unit(inv, h["project_id"])
        info = per_root[h["root"]].setdefault(u, {"hosts": set(), "projects": set()})
        info["hosts"].add(h["name"])
        info["projects"].add(h["project_id"])

    roots, movers = [], {}
    for root, units in sorted(per_root.items()):
        if not any(units_conflict(inv, a, b) for a in units for b in units):
            continue
        keep, why = _keeper(inv, root, units)
        stay = [keep]
        rest = sorted((u for u in units if u != keep), key=lambda u: -len(units[u]["hosts"]))
        moving = []
        for u in rest:
            if any(units_conflict(inv, u, s) for s in stay):
                moving.append(u)
            else:
                stay.append(u)
        roots.append({
            "root": root, "keep": unit_label(inv, keep), "keep_reason": why,
            "stays": [unit_label(inv, u) for u in stay],
            "moves": [unit_label(inv, u) for u in moving],
        })
        for u in moving:
            m = movers.setdefault(u, {"leaving": [], "all_hosts": set()})
            m["all_hosts"] |= units[u]["hosts"]
            hosts = sorted(units[u]["hosts"])
            live = [n for n in hosts if inv.hosts[n]["dns_status"] == "live"]
            m["leaving"].append({"root": root, "hosts": len(hosts), "live": live, "names": hosts[:200],
                                 "dns_checked": any(inv.hosts[n]["dns_status"] for n in hosts)})

    with db.session() as c:
        cand = {r["domain"]: dict(r) for r in c.execute("SELECT * FROM candidates")}

    moves = []
    for u, m in movers.items():
        pids = unit_projects(inv, u)
        planned = sorted({inv.projects[p]["planned_domain"] for p in pids if inv.projects[p]["planned_domain"]})
        moves.append({"unit": unit_label(inv, u), "projects": [inv.project_name(p) for p in pids],
                      "leaving": m["leaving"], "planned_domains": planned, "burned": _burned(inv, u, m["all_hosts"]),
                      "checks": [_planned_check(inv, u, d, cand) for d in planned]})
    moves.sort(key=lambda m: -sum(x["hosts"] for x in m["leaving"]))

    remaining = _after_moves(inv, movers)
    return {"roots": roots, "moves": moves, "remaining": remaining}


def _burned(inv, unit, hosts):
    """Old certs that put this unit's names next to a unit it must stay apart from. Those pairings are
    public forever, so the names on them must never be reused, even on the new domain."""
    out = defaultdict(lambda: {"certs": set(), "names": set()})
    for n in hosts:
        for k in inv.host_certs.get(n, ()):
            for other in inv.cert_names[k]:
                h = inv.hosts.get(other)
                if not h or h["ignored"] or h["project_id"] is None:
                    continue
                ou = _unit(inv, h["project_id"])
                if units_conflict(inv, unit, ou):
                    e = out[unit_label(inv, ou)]
                    e["certs"].add(k)
                    e["names"].add(n)
    return [{"with": w, "certs": len(e["certs"]), "names": sorted(e["names"])} for w, e in sorted(out.items())]


def _planned_check(inv, unit, domain, cand):
    """Problems with putting `unit` on `domain`, judged from the inventory and the last candidate check."""
    issues = []
    r = root_of(domain)
    for h in inv.visible_hosts():
        if h["root"] == r and h["project_id"] is not None:
            other = _unit(inv, h["project_id"])
            if units_conflict(inv, unit, other):
                issues.append(f"{r} already hosts {unit_label(inv, other)}, which this must stay apart from")
                break
    for pid, p in inv.projects.items():
        if p["planned_domain"] and root_of(p["planned_domain"]) == r:
            other = _unit(inv, pid)
            if units_conflict(inv, unit, other):
                issues.append(f"{p['name']} is also planned for {r}, and the two must stay apart")
    c = cand.get(domain) or cand.get(r)
    if not c:
        issues.append("not vetted yet: run a candidate check")
        verdict = "unchecked"
    else:
        verdict = c["verdict"]
        if verdict == "linked":
            issues.append("CT history already ties this domain to your other domains")
        elif verdict == "has_history":
            issues.append("domain has prior certificates; review before using")
    return {"domain": domain, "verdict": verdict, "issues": issues, "ok": not issues}


def _after_moves(inv, movers):
    """Re-run the violation check as if every moving unit had left its old roots
    (old names decommissioned, new names on a fresh domain with their own certs)."""
    moved = set().union(*(m["all_hosts"] for m in movers.values())) if movers else set()
    sim = copy.copy(inv)
    sim.hosts = {k: dict(v) for k, v in inv.hosts.items()}
    for n in moved:
        sim.hosts[n]["ignored"] = 1
    sim._by_root = None
    left = violations(sim)
    for v in left:
        ga = next((p["exposure_group"] for p in inv.projects.values() if p["name"] == v["a"]), "")
        gb = next((p["exposure_group"] for p in inv.projects.values() if p["name"] == v["b"]), "")
        if v["rule"] == "pair rule" and ga and ga == gb:
            v["fix"] = (f"Both are in exposure group {ga}, which moves as one unit. Put them in different groups "
                        "so the plan can split them.")
        elif v["cause"] == "same certificate":
            v["fix"] = ("These hostnames already sit on a shared certificate, which stays public forever. "
                        "Rotate one side's hostnames to new names and issue separate certificates from now on.")
        elif v["cause"] == "redirect":
            v["fix"] = "One project's hosts redirect to the other's. Remove the redirect; serve a plain 404 or retire the name instead."
        elif v["cause"] == "indirect":
            v["fix"] = "Linked through other hosts: follow the path and break the weakest link (often an unassigned host)."
        else:
            v["fix"] = "Still sharing a root: set a keep group on the domain or adjust exposure groups."
    return left


# --- candidate domains -------------------------------------------------------------------------

def check_candidate(domain):
    """Vet a domain you plan to move a project to. Clean = no CT history and nothing linking it to you."""
    domain = db.normalize_domain(domain)
    inv = analyze.Inventory()
    certs, src, errors = [], None, {}
    for name in ("crtsh_pg", "crtsh_json", "certspotter"):
        try:
            certs, _ = sources.CERT_SOURCES[name](domain)
            src = name
            break
        except Exception as e:
            errors[name] = str(e)[:200]
    if src is None:
        raise sources.SourceError(f"could not query CT for {domain}: {errors}")

    r = root_of(domain)
    names = sorted({n for c in certs for n in c["sans"]})
    linked = sorted(n for n in names if root_of(n) in inv.owned_roots and root_of(n) != r)
    already_inventory = r in inv.owned_roots

    registered = None
    try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = ["1.1.1.1", "8.8.8.8"]
        res.lifetime = 6
        res.resolve(r, "NS")
        registered = True
    except dns.resolver.NXDOMAIN:
        registered = False
    except Exception:
        pass

    if linked:
        verdict = "linked"
    elif certs:
        verdict = "has_history"
    else:
        verdict = "clean"
    detail = {
        "source": src, "certs": len(certs), "names": names[:300], "linked_names": linked[:100],
        "in_inventory": already_inventory, "registered": registered,
        "first_cert": min((c["not_before"] or "" for c in certs), default=None),
        "notes": _candidate_notes(verdict, registered, already_inventory),
    }
    with db.session() as c:
        c.execute("INSERT OR REPLACE INTO candidates(domain, checked_at, verdict, detail) VALUES (?,?,?,?)",
                  (domain, db.now(), verdict, json.dumps(detail)))
    return {"domain": domain, "verdict": verdict, **detail}


def _candidate_notes(verdict, registered, in_inv):
    notes = []
    if verdict == "clean":
        notes.append("No certificates have ever been logged for this domain.")
    if verdict == "has_history":
        notes.append("Certificates exist for this domain. If it was bought second-hand, check who used it before.")
    if verdict == "linked":
        notes.append("A certificate already names this domain together with one of yours. An attacker can follow it.")
    if registered is False:
        notes.append("Not registered (NXDOMAIN at the root). You'd need to buy it.")
    if in_inv:
        notes.append("Already in your inventory. Check which projects already live there.")
    return notes


def candidates():
    with db.session() as c:
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in c.execute("SELECT * FROM candidates ORDER BY domain")]


ROTATION_CHECKLIST = [
    "Register the new domain with WHOIS privacy and, if you can, a different registrar account from the old one.",
    "Issue certificates for the new domain on their own. Never put old-domain and new-domain names on the same cert.",
    "Prefer a wildcard certificate (*.newdomain) so individual hostnames stop showing up in CT logs.",
    "Don't redirect old hostnames to the new domain. A 301 hands the new domain to anyone who visits the old name.",
    "After cutover, delete the old DNS records. The old names stay in CT logs forever, but they shouldn't lead anywhere.",
    "Avoid OV/EV certificates that show the same organisation name: crt.sh can be searched by organisation.",
    "Keep hosting separate where it matters (IP ranges, CDN account, analytics or tracking IDs, favicon), since those can be pivoted on too.",
    "Add the new domain to crtwatch and give the project rules for it, so monitoring picks up any slip.",
]
