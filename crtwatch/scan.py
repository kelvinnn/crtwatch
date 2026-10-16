"""Pull certificates and names for inventory domains and record what changed."""
import json
import logging
import shutil
from concurrent.futures import ThreadPoolExecutor

from . import db, notify, sources

log = logging.getLogger("crtwatch.scan")

DEFAULT_CERT_CHAIN = ["crtsh_pg", "crtsh_json", "certspotter"]


def default_name_sources():
    names = ["shodanct"]
    if shutil.which("subfaster"):
        names.append("subfaster")
    return names


def scan_domain(domain_name, cert_chain=None, name_sources=None, every_cert_source=False):
    """Scan one inventory domain. Tries cert sources in order and stops at the first that works,
    unless every_cert_source is set, in which case all are run and merged."""
    cert_chain = cert_chain or DEFAULT_CERT_CHAIN
    name_sources = default_name_sources() if name_sources is None else name_sources

    with db.session() as c:
        dom = c.execute("SELECT * FROM domains WHERE name=?", (domain_name,)).fetchone()
        if not dom:
            raise ValueError(f"{domain_name} is not in the inventory")
        scan_id = c.execute(
            "INSERT INTO scans(domain_id, started_at, status) VALUES (?,?, 'running')", (dom["id"], db.now())
        ).lastrowid

    try:
        return _run(domain_name, dom, scan_id, cert_chain, name_sources, every_cert_source)
    except Exception as e:
        # Never leave a scan row stuck on "running".
        with db.session() as c:
            c.execute("UPDATE scans SET finished_at=?, status='failed', stage=NULL, error=COALESCE(error, ?) WHERE id=?",
                      (db.now(), json.dumps({"scan": str(e)[:500]}), scan_id))
            c.execute("UPDATE domains SET last_scan_status='failed' WHERE id=?", (dom["id"],))
        raise


STAGES = {
    "crtsh_pg": "querying the crt.sh database",
    "crtsh_json": "crt.sh database failed, trying the crt.sh JSON API",
    "certspotter": "crt.sh unavailable, trying CertSpotter",
    "shodanct": "fetching extra names from Shodan CT",
    "subfaster": "running subfaster",
}


def _stage(scan_id, text):
    with db.session() as c:
        c.execute("UPDATE scans SET stage=? WHERE id=?", (text, scan_id))


def _run(domain_name, dom, scan_id, cert_chain, name_sources, every_cert_source):
    used, errors, certs, names = [], {}, [], set()
    for name in cert_chain:
        _stage(scan_id, STAGES.get(name, name))
        try:
            got, _ = sources.CERT_SOURCES[name](domain_name)
            certs.extend(got)
            used.append(name)
            log.info("%s: %s returned %d certs", domain_name, name, len(got))
            if not every_cert_source:
                break
        except Exception as e:
            errors[name] = str(e)[:500]
            log.warning("%s: %s failed: %s", domain_name, name, e)
    for name in name_sources:
        _stage(scan_id, STAGES.get(name, name))
        try:
            _, got = sources.NAME_SOURCES[name](domain_name)
            names.update(got)
            used.append(name)
        except Exception as e:
            errors[name] = str(e)[:500]
            log.warning("%s: %s failed: %s", domain_name, name, e)

    if not used:
        with db.session() as c:
            c.execute("UPDATE scans SET finished_at=?, status='failed', stage=NULL, error=? WHERE id=?",
                      (db.now(), json.dumps(errors), scan_id))
            c.execute("UPDATE domains SET last_scan_status='failed' WHERE id=?", (dom["id"],))
        raise sources.SourceError(f"every source failed for {domain_name}: {errors}")

    _stage(scan_id, f"saving {len(certs)} certificates")
    stats = _store(domain_name, dom, certs, names, used)
    # Without certificate data we can't see links between names, so call it partial.
    status = "ok" if any(s in used for s in cert_chain) else "partial"
    with db.session() as c:
        c.execute(
            "UPDATE scans SET finished_at=?, status=?, stage=NULL, sources=?, hosts_total=?, new_hosts=?, new_certs=?, error=? WHERE id=?",
            (db.now(), status, json.dumps(used), stats["hosts_total"], stats["new_hosts"], stats["new_certs"],
             json.dumps(errors) if errors else None, scan_id),
        )
        c.execute("UPDATE domains SET last_scan_at=?, last_scan_status=? WHERE id=?", (db.now(), status, dom["id"]))
    notify.flush()
    return {"domain": domain_name, "status": status, "sources": used, "errors": errors, **stats}


def _store(domain_name, dom, certs, names, used):
    baseline = dom["last_scan_at"] is None
    new_certs = new_hosts = 0
    with db.session() as c:
        domains = c.execute("SELECT id, name, last_scan_at FROM domains").fetchall()
        by_id = {d["id"]: d for d in domains}
        host_first_seen, host_sources = {}, {}

        for cert in certs:
            row = c.execute("SELECT sans FROM certs WHERE key=?", (cert["key"],)).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO certs(key, source, crtsh_id, issuer, common_name, not_before, not_after, sans, first_seen_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (cert["key"], cert["source"], cert["crtsh_id"], cert["issuer"], cert["common_name"],
                     cert["not_before"], cert["not_after"], json.dumps(cert["sans"]), db.now()),
                )
                new_certs += 1
                if not baseline:
                    db.add_event(c, "new_cert", domain_name, cert["common_name"] or (cert["sans"] or ["?"])[0],
                                 {"sans": cert["sans"], "issuer": cert["issuer"], "not_before": cert["not_before"],
                                  "crtsh_id": cert["crtsh_id"]})
            else:
                merged = sorted(set(json.loads(row["sans"])) | set(cert["sans"]))
                c.execute("UPDATE certs SET sans=? WHERE key=?", (json.dumps(merged), cert["key"]))
            for san in cert["sans"]:
                c.execute("INSERT OR IGNORE INTO cert_hosts(cert_key, host) VALUES (?,?)", (cert["key"], san))
                nb = cert["not_before"] or db.now()
                host_first_seen[san] = min(host_first_seen.get(san, nb), nb)
                host_sources.setdefault(san, set()).add(cert["source"])

        name_src = [s for s in used if s in sources.NAME_SOURCES]
        for n in names:
            host_first_seen.setdefault(n, db.now())
            host_sources.setdefault(n, set()).update(name_src)

        for host, first_seen in host_first_seen.items():
            d = db.domain_for_host(domains, host)
            if d is None:
                continue  # belongs to nobody in the inventory; analysis reports these as foreign names
            row = c.execute("SELECT sources, first_seen_at FROM hosts WHERE name=?", (host,)).fetchone()
            if row is None:
                c.execute("INSERT INTO hosts(name, domain_id, sources, first_seen_at) VALUES (?,?,?,?)",
                          (host, d["id"], json.dumps(sorted(host_sources[host])), first_seen))
                new_hosts += d["id"] == dom["id"]
                # Only alert once the host's own domain has a baseline, otherwise the first scan floods.
                if by_id[d["id"]]["last_scan_at"] is not None:
                    db.add_event(c, "new_host", d["name"], host,
                                 {"sources": sorted(host_sources[host]), "first_seen": first_seen})
            else:
                srcs = sorted(set(json.loads(row["sources"])) | host_sources[host])
                c.execute("UPDATE hosts SET sources=?, first_seen_at=?, domain_id=? WHERE name=?",
                          (json.dumps(srcs), min(row["first_seen_at"], first_seen), d["id"], host))
        total = c.execute("SELECT COUNT(*) FROM hosts WHERE domain_id=?", (dom["id"],)).fetchone()[0]
    return {"certs": len(certs), "new_certs": new_certs, "new_hosts": new_hosts, "hosts_total": total,
            "baseline": baseline}


def scan_many(domain_names, workers=2, **kw):
    """crt.sh limits concurrent connections per IP, so keep workers low."""
    results = []

    def one(name):
        try:
            return scan_domain(name, **kw)
        except Exception as e:
            return {"domain": name, "status": "failed", "error": str(e)}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for r in pool.map(one, domain_names):
            results.append(r)
    return results


def enabled_domains():
    with db.session() as c:
        return [r["name"] for r in c.execute("SELECT name FROM domains WHERE enabled=1 ORDER BY name")]
