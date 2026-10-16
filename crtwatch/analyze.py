"""Turn hosts + certificates into "who can find whom".

An attacker's pivots, both free and public:
  root pivot  found a.shop.acme.com -> query crt.sh for %.acme.com -> every name under acme.com
  cert pivot  open any cert for a host -> read every SAN on it -> follow those names' roots too
Blast radius of a project = everything reachable by repeating those two pivots from its hosts.
"""
import fnmatch
import json
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache

import tldextract

from . import db

_extract = tldextract.TLDExtract(suffix_list_urls=())  # bundled public suffix list, no network

# A cert carrying names from this many roots you don't own is a hosting provider's shared cert
# (old Cloudflare SNI certs, status-page vendors). The foreign names on it aren't yours.
PROVIDER_ROOTS = 3
# Names that only ever appear on CDN / hosting certs. A cert carrying one is a provider cert.
PROVIDER_HINTS = {"cloudflaressl.com", "cloudflare-dns.com", "incapsula.com", "incapdns.net", "fastly.net",
                  "fastlylb.net", "akamaized.net", "edgekey.net", "azureedge.net", "herokuapp.com",
                  "netlify.app", "vercel.app", "pantheonsite.io", "wpengine.com", "squarespace.com"}


@lru_cache(maxsize=200_000)
def root_of(host):
    bare = host[2:] if host.startswith("*.") else host
    r = _extract(bare)
    return getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain or bare


def _specificity(pattern):
    return (sum(ch not in "*?[]" for ch in pattern), len(pattern))


class Inventory:
    def __init__(self):
        with db.session() as c:
            self.domains = [dict(r) for r in c.execute("SELECT * FROM domains ORDER BY name")]
            self.projects = {r["id"]: dict(r) for r in c.execute("SELECT * FROM projects ORDER BY name")}
            self.rules = [dict(r) for r in c.execute("SELECT * FROM rules")]
            self.hosts = {r["name"]: dict(r) for r in c.execute("SELECT * FROM hosts")}
            self.certs = {r["key"]: dict(r) for r in c.execute("SELECT * FROM certs")}
            pairs = c.execute("SELECT cert_key, host FROM cert_hosts").fetchall()
            self.separations = {frozenset((r[0], r[1])) for r in c.execute("SELECT project_a, project_b FROM separations")}
        dom_by_id = {d["id"]: d["name"] for d in self.domains}
        now = datetime.now(timezone.utc).isoformat()
        self.cert_names = defaultdict(set)
        self.host_certs = defaultdict(set)
        for k, h in pairs:
            self.cert_names[k].add(h)
            self.host_certs[h].add(k)
        for cert in self.certs.values():
            cert["active"] = bool(cert["not_after"]) and _norm_ts(cert["not_after"]) > now
        self.owned_roots = {root_of(d["name"]) for d in self.domains}
        rules = sorted(self.rules, key=lambda r: _specificity(r["pattern"]), reverse=True)
        for h in self.hosts.values():
            h["domain"] = dom_by_id.get(h["domain_id"])
            h["root"] = root_of(h["name"])
            h["project_id"], h["rule"] = None, None
            for r in rules:
                if fnmatch.fnmatchcase(h["name"], r["pattern"]):
                    h["project_id"], h["rule"] = r["project_id"], r["pattern"]
                    break
        self.provider_certs = set()
        for k, names in self.cert_names.items():
            foreign_roots = {root_of(n) for n in names} - self.owned_roots
            if len(foreign_roots) >= PROVIDER_ROOTS or foreign_roots & PROVIDER_HINTS:
                self.provider_certs.add(k)

    def visible_hosts(self):
        return [h for h in self.hosts.values() if not h["ignored"]]

    def project_name(self, pid):
        return self.projects[pid]["name"] if pid in self.projects else None


def _norm_ts(ts):
    s = str(ts).replace(" ", "T")
    return s if ("+" in s[10:] or s.endswith("Z")) else s + "+00:00"


# --- blast radius ------------------------------------------------------------------------------

def walk(inv, project_id):
    """Breadth-first walk of root and cert pivots starting from one project's hosts.
    Returns {host: (hop, how, parent_host)} so any reached host can be traced back to the start."""
    by_root = getattr(inv, "_by_root", None)
    if by_root is None:
        by_root = inv._by_root = defaultdict(list)
        for h in inv.visible_hosts():
            by_root[h["root"]].append(h["name"])
    start = [h["name"] for h in inv.visible_hosts() if h["project_id"] == project_id]
    seen = {n: (0, "own host", None) for n in start}
    frontier, roots_done, certs_done = list(start), set(), set()
    hop = 0
    while frontier:
        hop += 1
        nxt = []
        for name in frontier:
            r = root_of(name)
            if r not in roots_done:
                roots_done.add(r)
                for other in by_root.get(r, []):
                    if other not in seen:
                        seen[other] = (hop, f"crt.sh search for %.{r}", name)
                        nxt.append(other)
            for k in inv.host_certs.get(name, ()):
                if k in certs_done:
                    continue
                certs_done.add(k)
                for other in inv.cert_names[k]:
                    if other in inv.hosts and not inv.hosts[other]["ignored"] and other not in seen:
                        seen[other] = (hop, f"same certificate ({_cert_ref(inv, k)})", name)
                        nxt.append(other)
        frontier = nxt
    return seen, start, roots_done


def trace(seen, host):
    """Steps from the starting project to `host`, oldest first."""
    steps = []
    while host is not None:
        hop, how, parent = seen[host]
        if parent is not None:
            steps.append({"from": parent, "to": host, "how": how})
        host = parent
    return steps[::-1]


def blast_radius(inv, project_id):
    seen, start, roots_done = walk(inv, project_id)
    seen_simple = {n: (h, f"{how} (found via {parent})" if parent else how) for n, (h, how, parent) in seen.items()}
    exposed = defaultdict(lambda: {"hosts": 0, "hops": 99, "how": None, "example": None})
    for name, (h, how) in seen_simple.items():
        pid = inv.hosts[name]["project_id"]
        if pid == project_id:
            continue
        key = inv.project_name(pid) or "(unassigned)"
        e = exposed[key]
        e["hosts"] += 1
        if h < e["hops"]:
            e["hops"], e["how"], e["example"] = h, how, name
    return {
        "project": inv.project_name(project_id),
        "own_hosts": len(start),
        "reachable_hosts": len(seen) - len(start),
        "roots_touched": sorted(roots_done),
        "exposes": dict(sorted(exposed.items(), key=lambda kv: (kv[1]["hops"], -kv[1]["hosts"]))),
    }


def _cert_ref(inv, key):
    c = inv.certs.get(key) or {}
    return f"crt.sh id {c['crtsh_id']}" if c.get("crtsh_id") else key


# --- findings ----------------------------------------------------------------------------------

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def findings(inv):
    out = []
    hosts = inv.visible_hosts()

    # 1. Roots shared by several projects.
    per_root = defaultdict(lambda: defaultdict(list))
    for h in hosts:
        per_root[h["root"]][inv.project_name(h["project_id"]) or "(unassigned)"].append(h["name"])
    for root, projs in sorted(per_root.items()):
        named = {p: v for p, v in projs.items() if p != "(unassigned)"}
        if len(named) >= 2:
            out.append({
                "severity": "high", "kind": "shared_root", "root": root,
                "title": f"{len(named)} projects share {root}",
                "detail": ("Anyone who finds one of these projects can list the others with a single crt.sh "
                           f"search for %.{root}. Move each project to its own registrable domain, or accept "
                           "that they're linked."),
                "projects": {p: sorted(v)[:50] for p, v in sorted(named.items())},
                "counts": {p: len(v) for p, v in named.items()},
            })
        if "(unassigned)" in projs and named:
            out.append({
                "severity": "medium", "kind": "unassigned_on_shared_root", "root": root,
                "title": f"{len(projs['(unassigned)'])} unassigned host(s) under {root}",
                "detail": "Hosts nobody has claimed, sitting next to " + ", ".join(sorted(named)) +
                          ". Assign them to a project or decommission them.",
                "hosts": sorted(projs["(unassigned)"])[:200],
            })
        elif "(unassigned)" in projs:
            out.append({
                "severity": "low", "kind": "unassigned", "root": root,
                "title": f"{len(projs['(unassigned)'])} unassigned host(s) under {root}",
                "detail": "No project rule matches these yet.",
                "hosts": sorted(projs["(unassigned)"])[:200],
            })

    # 2. Certificates that put several projects (or several of your roots) on one cert.
    links = {}
    for k, names in inv.cert_names.items():
        mine = [n for n in names if n in inv.hosts and not inv.hosts[n]["ignored"]]
        if len(mine) < 2:
            continue
        projs = {inv.project_name(inv.hosts[n]["project_id"]) for n in mine} - {None}
        roots = {inv.hosts[n]["root"] for n in mine}
        if len(projs) < 2 and len(roots) < 2:
            continue
        sig = (frozenset(projs), frozenset(roots))
        L = links.setdefault(sig, {"certs": 0, "active": 0, "names": set(), "example": k, "latest": ""})
        L["certs"] += 1
        L["active"] += inv.certs.get(k, {}).get("active", False)
        L["names"].update(mine)
        nb = inv.certs.get(k, {}).get("not_before") or ""
        if nb > L["latest"]:
            L["latest"], L["example"] = nb, k
    for (projs, roots), L in links.items():
        if len(projs) >= 2:
            sev = "critical" if len(roots) >= 2 else "high"
            title = f"One certificate links projects {', '.join(sorted(projs))}"
            detail = ("Every SAN on a certificate is public. Seeing any one of these hosts reveals the others"
                      + (", even though they're on different domains. Domain separation doesn't help until "
                         "the certs are split." if len(roots) >= 2 else ". Issue a separate cert per project."))
        else:
            sev = "medium"
            title = f"One certificate ties together {', '.join(sorted(roots))}"
            detail = "The cert reveals that these domains belong to the same owner."
        out.append({
            "severity": sev, "kind": "cert_link", "title": title, "detail": detail,
            "projects": sorted(projs), "roots": sorted(roots), "certs": L["certs"], "active_certs": L["active"],
            "latest_issued": L["latest"], "example_cert": _cert_ref(inv, L["example"]),
            "hosts": sorted(L["names"])[:100],
        })

    # 3. Dangling CNAMEs (takeover candidates).
    for h in hosts:
        if h["dns_status"] == "dangling":
            out.append({
                "severity": "high", "kind": "dangling_cname", "root": h["root"],
                "title": f"{h['name']} points at a target that doesn't exist",
                "detail": "A CNAME whose target is NXDOMAIN can often be claimed by someone else (subdomain "
                          "takeover). Remove the record or reclaim the target. " + (h["dns_detail"] or ""),
                "hosts": [h["name"]],
            })

    # 4. Names on your certs under roots you haven't added: often your own forgotten domains.
    foreign = defaultdict(set)
    for k, names in inv.cert_names.items():
        if k in inv.provider_certs:
            continue
        if not any(n in inv.hosts for n in names):
            continue
        for n in names:
            r = root_of(n)
            if r not in inv.owned_roots:
                foreign[r].add(n)
    for r, names in sorted(foreign.items()):
        out.append({
            "severity": "info", "kind": "foreign_root", "root": r,
            "title": f"{r} shares certificates with your hosts but isn't in the inventory",
            "detail": "If you own it, add it as a domain so it's scanned and its projects are mapped.",
            "hosts": sorted(names)[:50],
        })

    # 5. Projects whose hostnames are published one by one instead of behind a wildcard.
    per_proj = defaultdict(list)
    for h in hosts:
        if h["project_id"] and not h["name"].startswith("*."):
            if any(inv.certs.get(k, {}).get("active") for k in inv.host_certs.get(h["name"], ())):
                per_proj[inv.project_name(h["project_id"])].append(h["name"])
    for p, names in sorted(per_proj.items()):
        if len(names) >= 3:
            out.append({
                "severity": "low", "kind": "named_certs", "title": f"{p}: {len(names)} hostnames on current certs",
                "detail": "Each named cert announces a hostname to the world. A wildcard cert (*.project-domain) "
                          "stops new names leaking. Old names stay in CT logs forever.",
                "hosts": sorted(names)[:100],
            })

    out.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["kind"], f.get("root", ""), f["title"]))
    return out


# --- views for the CLI / UI --------------------------------------------------------------------

def host_rows(inv, domain=None, project=None, q=None, include_ignored=True):
    rows = []
    for h in inv.hosts.values():
        if domain and h["domain"] != domain:
            continue
        pname = inv.project_name(h["project_id"])
        if project == "(unassigned)" and pname is not None:
            continue
        if project and project != "(unassigned)" and pname != project:
            continue
        if q and q.lower() not in h["name"]:
            continue
        if not include_ignored and h["ignored"]:
            continue
        ks = inv.host_certs.get(h["name"], ())
        certs = [inv.certs[k] for k in ks if k in inv.certs]
        others = set()
        for k in ks:
            if k not in inv.provider_certs:
                others |= inv.cert_names[k]
        others.discard(h["name"])
        rows.append({
            "name": h["name"], "domain": h["domain"], "root": h["root"], "project": pname, "rule": h["rule"],
            "ignored": bool(h["ignored"]), "sources": json.loads(h["sources"]), "first_seen": h["first_seen_at"],
            "certs": len(certs), "active_cert": any(c["active"] for c in certs),
            "latest_expiry": max((c["not_after"] or "" for c in certs), default=None),
            "co_names": len(others), "dns_status": h["dns_status"], "dns_detail": h["dns_detail"],
        })
    rows.sort(key=lambda r: (r["root"], r["name"].lstrip("*.")[::-1]))
    return rows


def summary():
    from . import separation
    inv = Inventory()
    fs = findings(inv)
    radius = [blast_radius(inv, pid) for pid in inv.projects]
    vis = inv.visible_hosts()
    viol = separation.violations(inv)
    return {
        "violations": viol,
        "counts": {
            "domains": len(inv.domains), "projects": len(inv.projects), "hosts": len(vis),
            "unassigned": sum(1 for h in vis if h["project_id"] is None),
            "ignored": len(inv.hosts) - len(vis), "certs": len(inv.certs),
            "findings": {s: sum(1 for f in fs if f["severity"] == s) for s in SEV_ORDER},
            "violations": len(viol),
            "grouped_projects": sum(1 for p in inv.projects.values() if p.get("exposure_group")),
        },
        "findings": fs,
        "blast_radius": sorted(radius, key=lambda r: -len(r["exposes"])),
    }


def cert_list(host):
    inv = Inventory()
    out = []
    for k in inv.host_certs.get(host, ()):
        c = inv.certs.get(k)
        if not c:
            continue
        out.append({**{x: c[x] for x in ("key", "source", "crtsh_id", "issuer", "common_name", "not_before",
                                           "not_after", "active")},
                    "sans": sorted(inv.cert_names[k]), "provider_shared": k in inv.provider_certs})
    return sorted(out, key=lambda c: c["not_before"] or "", reverse=True)
