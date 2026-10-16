"""SQLite storage. One file, no server, safe to copy around for backups."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("CRTWATCH_DB", os.path.join(os.getcwd(), "data", "crtwatch.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    added_at TEXT NOT NULL,
    last_scan_at TEXT,
    last_scan_status TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);
-- A rule maps hostnames to a project. Pattern is a glob: shop.acme.com, *.shop.acme.com, api-shop*.acme.io
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    UNIQUE (project_id, pattern)
);
CREATE TABLE IF NOT EXISTS certs (
    key TEXT PRIMARY KEY,            -- issuer:serial for crt.sh, tbs hash for certspotter
    source TEXT NOT NULL,
    crtsh_id INTEGER,
    issuer TEXT,
    common_name TEXT,
    not_before TEXT,
    not_after TEXT,
    sans TEXT NOT NULL,              -- JSON list of every DNS name on the cert
    first_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cert_hosts (
    cert_key TEXT NOT NULL REFERENCES certs(key) ON DELETE CASCADE,
    host TEXT NOT NULL,
    PRIMARY KEY (cert_key, host)
);
CREATE INDEX IF NOT EXISTS cert_hosts_host ON cert_hosts(host);
CREATE TABLE IF NOT EXISTS hosts (
    name TEXT PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    sources TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    ignored INTEGER NOT NULL DEFAULT 0,
    dns_status TEXT,
    dns_detail TEXT,
    dns_checked_at TEXT
);
CREATE INDEX IF NOT EXISTS hosts_domain ON hosts(domain_id);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    sources TEXT,
    hosts_total INTEGER,
    new_hosts INTEGER,
    new_certs INTEGER,
    error TEXT
);
-- Projects that must never be discoverable from each other, beyond what exposure groups say.
CREATE TABLE IF NOT EXISTS separations (
    project_a INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    project_b INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    PRIMARY KEY (project_a, project_b),
    CHECK (project_a < project_b)
);
-- Results of vetting a domain you plan to rotate a project to.
CREATE TABLE IF NOT EXISTS candidates (
    domain TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    domain TEXT,
    subject TEXT,
    detail TEXT,
    notified INTEGER NOT NULL DEFAULT 0
);
"""


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=60, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def session():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Columns added after the first release; added in place so existing databases keep working.
MIGRATIONS = [
    ("projects", "exposure_group", "TEXT NOT NULL DEFAULT ''"),  # same group = allowed to be seen together
    ("projects", "planned_domain", "TEXT NOT NULL DEFAULT ''"),  # where the project will be rotated to
    ("domains", "keep_group", "TEXT NOT NULL DEFAULT ''"),       # group that stays on this root when splitting
    ("scans", "stage", "TEXT"),                                   # what a running scan is doing right now
]


def running_scans(c, max_age_hours=2):
    """Scans in progress, from this process or any other (CLI, monitor). Rows older than
    max_age_hours are treated as abandoned: their process died without finishing."""
    rows = c.execute(
        "SELECT s.id, s.started_at, s.stage, d.name AS domain FROM scans s JOIN domains d ON d.id=s.domain_id"
        " WHERE s.status='running' ORDER BY s.id").fetchall()
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_hours * 3600
    live, stale = [], []
    for r in rows:
        (live if datetime.fromisoformat(r["started_at"]).timestamp() > cutoff else stale).append(dict(r))
    for r in stale:
        c.execute("UPDATE scans SET status='interrupted', stage=NULL, finished_at=? WHERE id=?", (now(), r["id"]))
    return live


def init():
    with session() as c:
        c.executescript(SCHEMA)
        for table, col, decl in MIGRATIONS:
            cols = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def add_separation(c, a_id, b_id):
    if a_id == b_id:
        raise ValueError("a project can't be separated from itself")
    a, b = sorted((a_id, b_id))
    c.execute("INSERT OR IGNORE INTO separations(project_a, project_b) VALUES (?,?)", (a, b))


def normalize_domain(name):
    name = name.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    name = name.split("/")[0]
    if name.startswith("*."):
        name = name[2:]
    return name


def add_domain(c, name, notes=""):
    name = normalize_domain(name)
    if not name or "." not in name:
        raise ValueError(f"not a domain: {name!r}")
    c.execute("INSERT OR IGNORE INTO domains(name, notes, added_at) VALUES (?,?,?)", (name, notes, now()))
    return c.execute("SELECT * FROM domains WHERE name=?", (name,)).fetchone()


def add_project(c, name, notes=""):
    name = name.strip()
    if not name:
        raise ValueError("project name is empty")
    c.execute("INSERT OR IGNORE INTO projects(name, notes) VALUES (?,?)", (name, notes))
    return c.execute("SELECT * FROM projects WHERE name=?", (name,)).fetchone()


def add_rule(c, project_id, pattern):
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        raise ValueError("pattern is empty")
    c.execute("INSERT OR IGNORE INTO rules(project_id, pattern) VALUES (?,?)", (project_id, pattern))


def domain_for_host(domains, host):
    """Longest inventory domain that `host` sits under, or None."""
    bare = host[2:] if host.startswith("*.") else host
    best = None
    for d in domains:
        if bare == d["name"] or bare.endswith("." + d["name"]):
            if best is None or len(d["name"]) > len(best["name"]):
                best = d
    return best


def add_event(c, kind, domain, subject, detail=None):
    c.execute(
        "INSERT INTO events(ts, kind, domain, subject, detail) VALUES (?,?,?,?,?)",
        (now(), kind, domain, subject, json.dumps(detail) if detail is not None else None),
    )
