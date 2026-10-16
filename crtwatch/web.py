"""Web dashboard + JSON API. `python -m crtwatch serve`.

CRTWATCH_PASSWORD  require HTTP basic auth (any username, or CRTWATCH_USER). Set it on anything
                   that isn't bound to 127.0.0.1: the inventory is a map of your attack surface.
"""
import base64
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from . import analyze, db, dnscheck, probe, scan, separation

log = logging.getLogger("crtwatch.web")
SCAN_EVERY = None  # seconds, set by `serve --every`
STATIC = Path(__file__).parent / "static"



@asynccontextmanager
async def lifespan(_app):
    db.init()
    if SCAN_EVERY:
        log.info("background rescans every %ss", SCAN_EVERY)
        threading.Thread(target=_scheduler, daemon=True).start()
    yield


app = FastAPI(title="crtwatch", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    pw = os.environ.get("CRTWATCH_PASSWORD")
    if pw:
        user = os.environ.get("CRTWATCH_USER")
        ok = False
        h = request.headers.get("authorization", "")
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                ok = secrets.compare_digest(p, pw) and (user is None or secrets.compare_digest(u, user))
            except Exception:
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="crtwatch"'})
    return await call_next(request)


# --- background jobs ---------------------------------------------------------------------------

class Jobs:
    """One worker thread draining a queue. Adding work while it runs extends the queue instead of
    being refused. `recent` keeps the last finished items so the UI can say what just happened."""

    def __init__(self):
        self.lock = threading.Lock()
        self.queue = []          # domain names, or "dns"
        self.current = None
        self.current_started = None
        self.recent = []         # newest last
        self.worker = None

    def enqueue(self, domains=(), dns=False, http=False):
        with self.lock:
            for d in domains:
                if d != self.current and d not in self.queue:
                    self.queue.append(d)
            # DNS and HTTP checks always run after the scans they follow, DNS first (HTTP skips dead names).
            for item, wanted in (("dns", dns or (domains and os.environ.get("CRTWATCH_DNS") == "1")),
                                 ("http", http or (domains and os.environ.get("CRTWATCH_PROBE") == "1"))):
                if wanted:
                    if item in self.queue:
                        self.queue.remove(item)
                    self.queue.append(item)
            if self.worker is None or not self.worker.is_alive():
                self.worker = threading.Thread(target=self._drain, daemon=True)
                self.worker.start()

    def _drain(self):
        while True:
            with self.lock:
                if not self.queue:
                    self.current = None
                    return
                item = self.queue.pop(0)
                self.current, self.current_started = item, db.now()
            t0 = time.time()
            try:
                if item == "dns":
                    r = {"kind": "dns", "counts": dnscheck.check_hosts(), "status": "ok"}
                elif item == "http":
                    r = {"kind": "http", "counts": probe.probe_hosts(), "status": "ok"}
                else:
                    r = {"kind": "scan", **scan.scan_domain(item)}
            except Exception as e:
                log.exception("job %s failed", item)
                r = {"kind": item if item in ("dns", "http") else "scan", "domain": item, "status": "failed", "error": str(e)[:300]}
            r.update(finished_at=db.now(), seconds=round(time.time() - t0))
            with self.lock:
                self.recent = (self.recent + [r])[-20:]

    def snapshot(self):
        with db.session() as c:
            running = db.running_scans(c)  # every scan row still running, including CLI-started ones
        with self.lock:
            return {
                "running": bool(self.current or self.queue or running),
                "current": self.current, "current_started": self.current_started,
                "queue": list(self.queue), "recent": list(self.recent), "scans": running,
            }


jobs = Jobs()


def _scheduler():
    while True:
        time.sleep(SCAN_EVERY)
        jobs.enqueue(scan.enabled_domains())


# --- API ---------------------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/summary")
def get_summary():
    return analyze.summary()


@app.get("/api/domains")
def list_domains():
    with db.session() as c:
        rows = c.execute(
            "SELECT d.*, (SELECT COUNT(*) FROM hosts h WHERE h.domain_id=d.id) AS hosts,"
            " (SELECT error FROM scans s WHERE s.domain_id=d.id ORDER BY s.id DESC LIMIT 1) AS last_error"
            " FROM domains d ORDER BY name").fetchall()
        return [dict(r) for r in rows]


@app.post("/api/domains")
def add_domains(payload: dict = Body(...)):
    """{"names": "a.com\\nb.com"} or {"names": ["a.com", "b.com"]}"""
    names = payload.get("names", [])
    if isinstance(names, str):
        names = [n for chunk in names.replace(",", "\n").splitlines() for n in [chunk.strip()] if n]
    added, bad = [], []
    with db.session() as c:
        for n in names:
            try:
                added.append(db.add_domain(c, n, payload.get("notes", ""))["name"])
            except ValueError:
                bad.append(n)
    if payload.get("scan") and added:
        jobs.enqueue(added)
    return {"added": added, "invalid": bad}


@app.delete("/api/domains/{name}")
def delete_domain(name: str):
    with db.session() as c:
        c.execute("DELETE FROM domains WHERE name=?", (name,))
    return {"ok": True}


@app.patch("/api/domains/{name}")
def patch_domain(name: str, payload: dict = Body(...)):
    with db.session() as c:
        if "enabled" in payload:
            c.execute("UPDATE domains SET enabled=? WHERE name=?", (1 if payload["enabled"] else 0, name))
        if "notes" in payload:
            c.execute("UPDATE domains SET notes=? WHERE name=?", (payload["notes"], name))
        if "keep_group" in payload:
            c.execute("UPDATE domains SET keep_group=? WHERE name=?", (payload["keep_group"] or "", name))
    return {"ok": True}


@app.post("/api/scan")
def start_scan(payload: dict = Body(default={})):
    jobs.enqueue(payload.get("domains") or scan.enabled_domains(), dns=bool(payload.get("dns")), http=bool(payload.get("http")))
    return jobs.snapshot()


@app.post("/api/dns")
def start_dns():
    jobs.enqueue(dns=True)
    return jobs.snapshot()


@app.post("/api/probe")
def start_probe():
    jobs.enqueue(http=True)
    return jobs.snapshot()


@app.post("/api/probe/host")
def probe_one(host: str):
    """Check a single host right away (a few seconds at most)."""
    with db.session() as c:
        if not c.execute("SELECT 1 FROM hosts WHERE name=?", (host,)).fetchone():
            raise HTTPException(404, "unknown host")
    probe.probe_hosts([host])
    return analyze.probe_detail(host)


@app.get("/api/probe")
def get_probe(host: str):
    d = analyze.probe_detail(host)
    if d is None:
        raise HTTPException(404, "not probed yet")
    return d


@app.get("/api/jobs")
def job_state():
    return jobs.snapshot()


@app.get("/api/projects")
def list_projects():
    inv = analyze.Inventory()
    counts = {}
    for h in inv.visible_hosts():
        counts[h["project_id"]] = counts.get(h["project_id"], 0) + 1
    out = []
    for pid, p in inv.projects.items():
        out.append({**p, "hosts": counts.get(pid, 0),
                    "rules": [{"id": r["id"], "pattern": r["pattern"]} for r in inv.rules if r["project_id"] == pid]})
    return sorted(out, key=lambda p: p["name"].lower())


@app.post("/api/projects")
def add_project(payload: dict = Body(...)):
    with db.session() as c:
        try:
            p = db.add_project(c, payload.get("name", ""), payload.get("notes", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        for pat in payload.get("rules", []):
            db.add_rule(c, p["id"], pat)
        return dict(p)


@app.patch("/api/projects/{pid}")
def patch_project(pid: int, payload: dict = Body(...)):
    with db.session() as c:
        if payload.get("name"):
            c.execute("UPDATE projects SET name=? WHERE id=?", (payload["name"].strip(), pid))
        if "notes" in payload:
            c.execute("UPDATE projects SET notes=? WHERE id=?", (payload["notes"], pid))
        if "exposure_group" in payload:
            c.execute("UPDATE projects SET exposure_group=? WHERE id=?", ((payload["exposure_group"] or "").strip(), pid))
        if "planned_domain" in payload:
            d = payload["planned_domain"] or ""
            c.execute("UPDATE projects SET planned_domain=? WHERE id=?", (db.normalize_domain(d) if d else "", pid))
    return {"ok": True}


@app.delete("/api/projects/{pid}")
def delete_project(pid: int):
    with db.session() as c:
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return {"ok": True}


@app.post("/api/projects/{pid}/rules")
def add_rules(pid: int, payload: dict = Body(...)):
    pats = payload.get("patterns", [])
    if isinstance(pats, str):
        pats = [p.strip() for p in pats.replace(",", "\n").splitlines() if p.strip()]
    with db.session() as c:
        for p in pats:
            db.add_rule(c, pid, p)
    return {"ok": True}


@app.delete("/api/rules/{rid}")
def delete_rule(rid: int):
    with db.session() as c:
        c.execute("DELETE FROM rules WHERE id=?", (rid,))
    return {"ok": True}


@app.get("/api/hosts")
def list_hosts(domain: str = None, project: str = None, q: str = None, http: str = None):
    return analyze.host_rows(analyze.Inventory(), domain=domain, project=project, q=q, http=http)


@app.post("/api/hosts/assign")
def assign_hosts(payload: dict = Body(...)):
    """{"hosts": [...], "project_id": 3} adds exact-name rules; project_id null removes exact rules."""
    hosts = [h.lower() for h in payload.get("hosts", [])]
    pid = payload.get("project_id")
    with db.session() as c:
        for h in hosts:
            c.execute("DELETE FROM rules WHERE pattern=?", (h,))
            if pid:
                db.add_rule(c, pid, h)
    return {"ok": True}


@app.post("/api/hosts/ignore")
def ignore_hosts(payload: dict = Body(...)):
    with db.session() as c:
        c.executemany("UPDATE hosts SET ignored=? WHERE name=?",
                      [(1 if payload.get("ignored", True) else 0, h) for h in payload.get("hosts", [])])
    return {"ok": True}


@app.get("/api/certs")
def certs_for(host: str):
    return analyze.cert_list(host)


@app.get("/api/events")
def list_events(limit: int = 200):
    with db.session() as c:
        return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]


@app.get("/api/scans")
def list_scans(limit: int = 50):
    with db.session() as c:
        return [dict(r) for r in c.execute(
            "SELECT s.*, d.name AS domain FROM scans s LEFT JOIN domains d ON d.id=s.domain_id ORDER BY s.id DESC LIMIT ?",
            (limit,))]


@app.get("/api/separation")
def get_separation():
    inv = analyze.Inventory()
    with db.session() as c:
        pairs = [dict(r) for r in c.execute(
            "SELECT s.project_a, s.project_b, a.name AS a, b.name AS b FROM separations s"
            " JOIN projects a ON a.id=s.project_a JOIN projects b ON b.id=s.project_b ORDER BY a.name, b.name")]
    roots = sorted({analyze.root_of(d["name"]) for d in inv.domains})
    return {
        "projects": [{k: p[k] for k in ("id", "name", "exposure_group", "planned_domain")} for p in
                     sorted(inv.projects.values(), key=lambda p: (p["exposure_group"] or "~", p["name"].lower()))],
        "groups": sorted({p["exposure_group"] for p in inv.projects.values() if p["exposure_group"]}),
        "pairs": pairs,
        "domains": [{"name": d["name"], "keep_group": d["keep_group"]} for d in inv.domains],
        "roots": roots,
        "violations": separation.violations(inv),
        "plan": separation.rotation_plan(inv),
        "candidates": separation.candidates(),
        "checklist": separation.ROTATION_CHECKLIST,
    }


@app.post("/api/separations")
def add_pair(payload: dict = Body(...)):
    with db.session() as c:
        try:
            db.add_separation(c, int(payload["a"]), int(payload["b"]))
        except (ValueError, KeyError) as e:
            raise HTTPException(400, str(e))
    return {"ok": True}


@app.delete("/api/separations/{a}/{b}")
def delete_pair(a: int, b: int):
    x, y = sorted((a, b))
    with db.session() as c:
        c.execute("DELETE FROM separations WHERE project_a=? AND project_b=?", (x, y))
    return {"ok": True}


@app.post("/api/groups/target")
def group_target(payload: dict = Body(...)):
    d = payload.get("domain") or ""
    with db.session() as c:
        c.execute("UPDATE projects SET planned_domain=? WHERE exposure_group=?",
                  (db.normalize_domain(d) if d else "", payload["group"]))
    return {"ok": True}


@app.post("/api/candidates")
def check_candidate(payload: dict = Body(...)):
    """Blocking: queries crt.sh, can take up to a minute."""
    try:
        return separation.check_candidate(payload["domain"])
    except Exception as e:
        raise HTTPException(502, str(e)[:300])


@app.get("/api/export.json")
def export():
    return JSONResponse(analyze.summary(), headers={"Content-Disposition": "attachment; filename=crtwatch-report.json"})
