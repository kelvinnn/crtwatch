"""Resolve hosts to tell live names from stale CT history, and spot dangling CNAMEs."""
import os
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from . import db

RESOLVERS = os.environ.get("CRTWATCH_RESOLVERS", "1.1.1.1,8.8.8.8").split(",")


def _resolver():
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = RESOLVERS
    r.lifetime = 6
    return r


def check(host):
    r = _resolver()
    cname = None
    try:
        cname = str(r.resolve(host, "CNAME")[0].target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    addrs = []
    status = None
    for rtype in ("A", "AAAA"):
        try:
            addrs += [a.to_text() for a in r.resolve(host, rtype)]
        except dns.resolver.NXDOMAIN:
            status = "nxdomain"
            break
        except dns.resolver.NoAnswer:
            pass
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            status = status or "error"
    if cname and not addrs:
        try:
            r.resolve(cname, "A")
        except dns.resolver.NXDOMAIN:
            return "dangling", f"CNAME -> {cname} (NXDOMAIN)"
        except Exception:
            pass
    if addrs:
        return "live", (f"CNAME {cname} -> " if cname else "") + ", ".join(sorted(set(addrs))[:6])
    if status == "nxdomain":
        return "nxdomain", None
    return status or "no_address", (f"CNAME {cname}" if cname else None)


def check_hosts(names=None, workers=32):
    with db.session() as c:
        if names is None:
            names = [r["name"] for r in c.execute("SELECT name FROM hosts WHERE name NOT LIKE '*.%'")]
    names = [n for n in names if not n.startswith("*.")]

    def one(n):
        try:
            return n, *check(n)
        except Exception as e:
            return n, "error", str(e)[:200]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, names))
    with db.session() as c:
        c.executemany("UPDATE hosts SET dns_status=?, dns_detail=?, dns_checked_at=? WHERE name=?",
                      [(s, d, db.now(), n) for n, s, d in results])
    counts = {}
    for _, s, _ in results:
        counts[s] = counts.get(s, 0) + 1
    return counts
