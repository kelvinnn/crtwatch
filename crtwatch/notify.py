"""Send new-host / new-cert events to a webhook.

CRTWATCH_WEBHOOK_URL     where to POST. Unset = events are only kept in the database.
CRTWATCH_WEBHOOK_FORMAT  slack (default, {"text"}), discord ({"content"}) or json (raw event list).
"""
import json
import logging
import os
import urllib.request

from . import db
from .sources import SSL_CTX

log = logging.getLogger("crtwatch.notify")


def _line(e):
    detail = json.loads(e["detail"]) if e["detail"] else {}
    if e["kind"] == "new_host":
        return f"• new host `{e['subject']}` on {e['domain']}"
    if e["kind"] == "new_cert":
        sans = detail.get("sans", [])
        extra = f" (+{len(sans) - 5} more)" if len(sans) > 5 else ""
        return f"• new cert on {e['domain']} by {detail.get('issuer') or '?'}: {', '.join(sans[:5])}{extra}"
    if e["kind"] == "http_change":
        return f"• `{e['subject']}` now answers {detail.get('to')} (was {detail.get('from')})"
    return f"• {e['kind']} {e['subject']}"


def flush():
    url = os.environ.get("CRTWATCH_WEBHOOK_URL")
    fmt = os.environ.get("CRTWATCH_WEBHOOK_FORMAT", "slack")
    with db.session() as c:
        events = c.execute("SELECT * FROM events WHERE notified=0 ORDER BY id LIMIT 500").fetchall()
        if not events:
            return 0
        if url:
            text = f"crtwatch: {len(events)} new item(s) in Certificate Transparency\n" + "\n".join(
                _line(e) for e in events[:40])
            if len(events) > 40:
                text += f"\n…and {len(events) - 40} more"
            if fmt == "discord":
                body = {"content": text[:1900]}
            elif fmt == "json":
                body = {"events": [dict(e) for e in events]}
            else:
                body = {"text": text}
            try:
                req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=20, context=SSL_CTX).read()
            except Exception as e:
                log.warning("webhook failed, will retry next scan: %s", e)
                return 0
        c.executemany("UPDATE events SET notified=1 WHERE id=?", [(e["id"],) for e in events])
        return len(events)
