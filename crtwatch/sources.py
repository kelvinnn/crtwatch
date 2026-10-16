"""Where names come from.

Certificate Transparency sources return whole certificates (every SAN on them), which is what
lets us see when one cert ties two projects together. Name-only sources just add hostnames.

  crtsh_pg     crt.sh's public Postgres replica. No row cap, full SAN lists. Primary source.
  crtsh_json   crt.sh's JSON endpoint. Fallback; only returns the matching SANs, and 502s on big domains.
  certspotter  SSLMate CertSpotter API. Fallback with full SANs; keyless tier is rate limited,
               set CERTSPOTTER_API_KEY to lift it.
  shodanct     Shodan's CT hostname index (names only, keyless).
  subfaster    Runs the subfaster binary if it is on PATH, for non-CT passive sources (names only).
"""
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "crtwatch/1.0 (+asset inventory)"
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z0-9-]+$")


try:  # some Python builds ship an incomplete CA store; certifi's bundle is the reliable one
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()


class SourceError(Exception):
    pass


def _check(domain):
    if not DOMAIN_RE.match(domain):
        raise SourceError(f"refusing to query odd domain {domain!r}")


def _clean(name):
    name = name.strip().lower().rstrip(".")
    return name if name and " " not in name and "@" not in name else None


def _get(url, headers=None, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
        return resp.read()


def _retry(fn, attempts=4, base=5):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # network flakiness, replica conflicts, 5xx
            last = e
            if i < attempts - 1:
                time.sleep(base * (2 ** i))
    raise SourceError(str(last))


def _iso(v):
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.replace(microsecond=0).isoformat()
    return str(v)


# --- crt.sh Postgres ---------------------------------------------------------------------------

CRTSH_SQL = """
WITH ids AS (
    SELECT DISTINCT cai.certificate_id AS id
    FROM certificate_and_identities cai
    WHERE plainto_tsquery('certwatch', %(d)s) @@ identities(cai.certificate)
      AND (cai.name_value ILIKE ('%%.' || %(d)s) OR lower(cai.name_value) = %(d)s)
)
SELECT c.id,
       c.issuer_ca_id,
       ca.name,
       x509_commonName(c.certificate),
       x509_notBefore(c.certificate),
       x509_notAfter(c.certificate),
       encode(x509_serialNumber(c.certificate), 'hex'),
       ARRAY(SELECT DISTINCT lower(n) FROM x509_altNames(c.certificate, 2, TRUE) n)
FROM ids
JOIN certificate c ON c.id = ids.id
LEFT JOIN ca ON ca.id = c.issuer_ca_id
"""


def crtsh_pg(domain):
    _check(domain)
    import psycopg

    def run():
        dsn = os.environ.get("CRTSH_DSN", "host=crt.sh port=5432 dbname=certwatch user=guest")
        with psycopg.connect(dsn, autocommit=True, connect_timeout=20) as conn:
            try:
                conn.execute("SET statement_timeout = 0")
            except Exception:
                pass
            return conn.execute(CRTSH_SQL, {"d": domain}).fetchall()

    rows = _retry(run)
    certs = {}
    for cid, issuer_id, issuer, cn, nb, na, serial, sans in rows:
        # The precertificate and the final certificate share issuer+serial; keep one.
        key = f"crtsh:{issuer_id}:{serial}"
        names = sorted({n for n in (_clean(s) for s in (sans or [])) if n})
        if cn and _clean(cn) and _clean(cn) not in names:
            names.append(_clean(cn))
        prev = certs.get(key)
        if prev:
            prev["sans"] = sorted(set(prev["sans"]) | set(names))
            prev["crtsh_id"] = min(prev["crtsh_id"], cid)
            continue
        certs[key] = {
            "key": key, "source": "crtsh_pg", "crtsh_id": cid, "issuer": issuer,
            "common_name": cn, "not_before": _iso(nb), "not_after": _iso(na), "sans": names,
        }
    return list(certs.values()), []


# --- crt.sh JSON -------------------------------------------------------------------------------

def crtsh_json(domain):
    _check(domain)
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    data = json.loads(_retry(lambda: _get(url, timeout=300)))
    certs = {}
    for r in data:
        key = f"crtsh:{r.get('issuer_ca_id')}:{r.get('serial_number')}"
        names = {n for n in (_clean(s) for s in r.get("name_value", "").split("\n")) if n}
        if r.get("common_name") and _clean(r["common_name"]):
            names.add(_clean(r["common_name"]))
        c = certs.setdefault(key, {
            "key": key, "source": "crtsh_json", "crtsh_id": r.get("id"), "issuer": r.get("issuer_name"),
            "common_name": r.get("common_name"), "not_before": r.get("not_before"),
            "not_after": r.get("not_after"), "sans": [],
        })
        c["sans"] = sorted(set(c["sans"]) | names)
    return list(certs.values()), []


# --- CertSpotter -------------------------------------------------------------------------------

def certspotter(domain):
    _check(domain)
    headers = {}
    if os.environ.get("CERTSPOTTER_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["CERTSPOTTER_API_KEY"]
    base = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(
        [("domain", domain), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")]
    )
    certs, after = [], None
    while True:
        url = base + (f"&after={after}" if after else "")
        try:
            page = json.loads(_get(url, headers=headers, timeout=60))
        except urllib.error.HTTPError as e:
            if e.code == 429 and certs:
                break  # keep what we have; the next scan picks up the rest
            raise SourceError(f"certspotter HTTP {e.code}")
        if not page:
            break
        for it in page:
            issuer = it.get("issuer") or {}
            certs.append({
                "key": "cs:" + it["tbs_sha256"], "source": "certspotter", "crtsh_id": None,
                "issuer": issuer.get("friendly_name") or issuer.get("name"), "common_name": None,
                "not_before": it.get("not_before"), "not_after": it.get("not_after"),
                "sans": sorted({n for n in (_clean(s) for s in it.get("dns_names", [])) if n}),
            })
        after = page[-1]["id"]
    return certs, []


# --- name-only sources -------------------------------------------------------------------------

def shodanct(domain):
    _check(domain)
    data = json.loads(_retry(lambda: _get(f"https://ctl.shodan.io/api/v1/domain/{domain}/hostnames", timeout=60), attempts=2))
    return [], [n for n in (_clean(x) for x in data) if n]


def subfaster(domain):
    _check(domain)
    exe = shutil.which("subfaster")
    if not exe:
        raise SourceError("subfaster not on PATH")
    out = subprocess.run([exe, "-d", domain, "-silent"], capture_output=True, text=True, timeout=600)
    return [], [n for n in (_clean(x) for x in out.stdout.splitlines()) if n]


CERT_SOURCES = {"crtsh_pg": crtsh_pg, "crtsh_json": crtsh_json, "certspotter": certspotter}
NAME_SOURCES = {"shodanct": shodanct, "subfaster": subfaster}
