"""HTTP check: visit each hostname and record what answers.

This is the one *active* part of crtwatch: it connects to your hosts. It's only run when asked
(`crtwatch probe`, the dashboard's HTTP check button, or CRTWATCH_PROBE=1 for scheduled scans).

Safety:
  - hosts that resolve only to private, loopback or link-local addresses are skipped,
    and redirects into such addresses are never followed (no poking at internal services or
    cloud metadata endpoints from a server)
  - bodies are capped, and only text is kept: the dashboard shows it escaped, and the optional
    rendered preview runs in a sandbox with scripts and network loads blocked
"""
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

from . import db
from .sources import SSL_CTX

UA = "Mozilla/5.0 (compatible; crtwatch/1.0; +asset inventory check)"
MAX_BODY = 256 * 1024     # bytes read per response
KEEP_HTML = 24 * 1024     # bytes of HTML kept for the rendered preview
MAX_REDIRECTS = 5
# Off by default. Turn on (--allow-private / CRTWATCH_PROBE_PRIVATE=1) to check internal hostnames from
# inside your own network.
ALLOW_PRIVATE = os.environ.get("CRTWATCH_PROBE_PRIVATE") == "1"

_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


class Blocked(Exception):
    pass


def _public(hostname):
    """True if the name resolves and at least one address is public."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ConnectionError(f"DNS: {e.strerror or e}")
    addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    return any(a.is_global for a in addrs)


def _request(url, verify=True, timeout=8):
    parts = urlsplit(url)
    host = parts.hostname
    if not ALLOW_PRIVATE and not _public(host):
        raise Blocked(f"{host} resolves only to private/internal addresses")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=SSL_CTX if verify else _INSECURE)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
                                           "Accept-Encoding": "identity", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
        return resp.status, resp.reason, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


def _fetch(start_url, timeout):
    """Follow redirects by hand so every hop is recorded."""
    out = {"url": start_url, "redirects": [], "tls_error": None}
    url = start_url
    verify = True
    for _ in range(MAX_REDIRECTS + 1):
        try:
            status, reason, headers, body = _request(url, verify, timeout)
        except ssl.SSLCertVerificationError as e:
            out["tls_error"] = (e.verify_message or str(e))[:200]
            verify = False  # still look at what's there; the bad certificate is recorded
            status, reason, headers, body = _request(url, verify, timeout)
        if 300 <= status < 400 and headers.get("location"):
            nxt = urljoin(url, headers["location"].strip())
            out["redirects"].append({"status": status, "from": url, "to": nxt})
            if urlsplit(nxt).scheme not in ("http", "https"):
                break
            url = nxt
            continue
        break
    out.update(final_url=url, status=status, reason=reason, headers=headers, body=body)
    return out


def _text(body, content_type):
    charset = "utf-8"
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    if m:
        charset = m.group(1)
    else:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:2048], re.I)
        if m:
            charset = m.group(1).decode("ascii", "ignore")
    try:
        return body.decode(charset, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def summarize(body, content_type):
    """Title and a short readable snippet of a response body."""
    text = _text(body, content_type)
    is_html = "html" in (content_type or "").lower() or text.lstrip()[:15].lower().startswith(("<!doctype html", "<html"))
    title = None
    if is_html:
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:200] or None
        visible = re.sub(r"<(head|script|style|noscript|template|svg)[^>]*>.*?</\1>", " ", text, flags=re.I | re.S)
        visible = re.sub(r"<!--.*?-->", " ", visible, flags=re.S)
        visible = html.unescape(re.sub(r"<[^>]+>", " ", visible))
    else:
        visible = text
    snippet = re.sub(r"\s+", " ", visible).strip()[:600]
    return title, snippet, (text[:KEEP_HTML] if is_html else None)


def probe(host, timeout=8):
    """Try https, then http. Returns a dict ready to store."""
    result = {"host": host, "status": None, "error": None}
    for scheme in ("https", "http"):
        try:
            r = _fetch(f"{scheme}://{host}/", timeout)
        except Blocked as e:
            result.update(error=f"skipped: {e}", scheme=scheme)
            return result
        except Exception as e:
            result.update(error=_short_error(e), scheme=scheme)
            continue
        ctype = r["headers"].get("content-type", "")
        title, snippet, page = summarize(r["body"], ctype)
        first = r["redirects"][0]["status"] if r["redirects"] else r["status"]
        result.update(
            scheme=scheme, url=r["url"], final_url=r["final_url"], status=first, final_status=r["status"], reason=r["reason"],
            title=title, content_type=ctype.split(";")[0].strip() or None, server=r["headers"].get("server"),
            length=len(r["body"]), redirects=r["redirects"], tls_error=r["tls_error"], snippet=snippet,
            html=page if 200 <= r["status"] < 300 else None, error=None,  # preview is of the page you end up on
        )
        return result
    return result


def _short_error(e):
    if isinstance(e, socket.timeout) or "timed out" in str(e):
        return "timeout"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    if isinstance(e, ssl.SSLError):
        return f"TLS: {getattr(e, 'reason', None) or e}"[:200]
    return (str(e) or type(e).__name__)[:200]


def status_class(status, error=None):
    if status is None:
        return "skipped" if (error or "").startswith("skipped") else "down"
    return f"{status // 100}xx"


def probe_hosts(names=None, workers=16, include_dead=False):
    """Probe hosts and store results. By default skips wildcards, ignored hosts, and names DNS says
    don't exist (run a DNS check first to make this faster)."""
    with db.session() as c:
        if names is None:
            q = "SELECT name, dns_status FROM hosts WHERE ignored=0 AND name NOT LIKE '*.%'"
            rows = c.execute(q).fetchall()
            names = [r["name"] for r in rows if include_dead or r["dns_status"] not in ("nxdomain", "no_address")]
        prev = {r["host"]: dict(r) for r in c.execute("SELECT host, status, error FROM probes")}
    names = [n for n in names if not n.startswith("*.")]

    def one(n):
        try:
            return probe(n)
        except Exception as e:  # never let one host kill the batch
            return {"host": n, "status": None, "error": _short_error(e)}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, names))

    counts = {}
    with db.session() as c:
        for r in results:
            cls = status_class(r.get("status"), r.get("error"))
            counts[cls] = counts.get(cls, 0) + 1
            c.execute(
                "INSERT OR REPLACE INTO probes(host, checked_at, scheme, url, final_url, status, final_status, reason, title,"
                " content_type, server, length, redirects, tls_error, snippet, html, error)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["host"], db.now(), r.get("scheme"), r.get("url"), r.get("final_url"), r.get("status"),
                 r.get("final_status"), r.get("reason"), r.get("title"), r.get("content_type"), r.get("server"), r.get("length"),
                 json.dumps(r.get("redirects") or []), r.get("tls_error"), r.get("snippet"), r.get("html"),
                 r.get("error")),
            )
            old = prev.get(r["host"])
            if old and status_class(old["status"], old["error"]) != cls and cls != "skipped":
                dom = c.execute("SELECT d.name FROM hosts h JOIN domains d ON d.id=h.domain_id WHERE h.name=?",
                                (r["host"],)).fetchone()
                db.add_event(c, "http_change", dom["name"] if dom else None, r["host"],
                             {"from": old["status"] or old["error"], "to": r.get("status") or r.get("error")})
    from . import notify
    notify.flush()
    return counts


def redirect_hosts(redirects, final_url):
    """Every hostname a redirect chain passes through, after the first."""
    hosts = []
    for hop in redirects or []:
        h = (urlsplit(hop["to"]).hostname or "").lower()
        if h and h not in hosts:
            hosts.append(h)
    if final_url:
        h = (urlsplit(final_url).hostname or "").lower()
        if h and h not in hosts:
            hosts.append(h)
    return hosts
