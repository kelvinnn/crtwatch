# 📗 crtwatch user guide

The complete reference. New to crtwatch? Start with **[📘 Getting started](getting-started.md)**, which walks through everything step by step.

- [Concepts](#concepts)
- [Typical workflow](#typical-workflow)
- [Command reference](#command-reference)
- [Importing a mapping from CSV](#importing-a-mapping-from-csv)
- [Monitoring and alerts](#monitoring-and-alerts)
- [Settings](#settings)
- [HTTP API](#http-api)
- [Troubleshooting](#troubleshooting)

## Concepts

| Term | Meaning |
|---|---|
| **Domain** | A domain you own and want scanned. Add the registrable root (`acme.com`, not `shop.acme.com`), because that's what an attacker searches for. |
| **Host** | A hostname found in CT logs (or by an extra name source) under one of your domains. Wildcards such as `*.acme.com` are kept as hosts too. |
| **Project** | A product or system. Hosts are mapped to projects by patterns. |
| **Pattern** | A glob such as `shop.acme.com`, `*.shop.acme.com` or `shop-api*.acme.io`. `*` matches anything, **including dots**, so `*.shop.acme.com` also matches `a.b.shop.acme.com`. When several patterns match a host, the most specific one wins: the one with the most literal characters. |
| **Ignored host** | A name you don't want counted, such as a vendor's hostname that shows up on a shared certificate. Ignored hosts are left out of findings, violations and the attacker walk. |
| **Exposure group** | A label on a project. Projects in the same group may be seen together. Projects in different groups must never be reachable from each other. A project with no group is not checked. |
| **Pair rule** | "Project A must never be seen with project B", for cases groups don't cover. |
| **Unit** | What the rotation plan moves as a whole: an entire exposure group, or a single project that has no group. |
| **Keep group** | On a domain that has to be split, the group that stays. If you don't set one, crtwatch picks the group that owns the apex or `www` host, otherwise the group with the most hosts there. |
| **Planned domain** | Where a project or group will move to. The plan checks it against your inventory and against CT history. |
| **Burned names** | Hostnames that old certificates already show next to a project they must stay apart from. CT logs are permanent, so never reuse these names, even on a new domain. |
| **Baseline** | The first scan of a domain. It fills the inventory without raising alerts. Later scans report what's new. |

## Typical workflow

1. **Add your domains** (Domains tab, or `crtwatch domain add`). Each one is queued and scanned; the banner under the menu shows the current step and elapsed time.
2. **Describe your projects** (Projects tab, `crtwatch project add`, or a [CSV import](#importing-a-mapping-from-csv)).
3. **Triage what's left** (Hosts tab → *(unassigned)*). Assign hosts to projects, or ignore names that aren't yours. Click a host to see its certificates and every other name on them.
4. **Resolve DNS** (*DNS check*, or `crtwatch dns`). This separates names that are still live from names that only exist in CT history, and flags dangling CNAMEs.
5. **Set exposure groups** (Separation tab, or `crtwatch group`). Add pair rules for exceptions.
6. **Read the violations.** Each pair comes with its cause (same root domain, same certificate, or an indirect chain) and the step-by-step path an attacker would follow.
7. **Read the rotation plan.** If the automatic choice of which group stays is wrong, set the keep group. For each unit that has to move:
   - pick a new domain and vet it (*Check*, or `crtwatch candidate`);
   - record it as the planned domain (`crtwatch target --group NAME domain`);
   - migrate the project;
   - delete the DNS records of the old hostnames listed as "still live";
   - never reuse the burned names.
8. **Add the new domain** to crtwatch, update the project's patterns, and keep monitoring running so you notice if anything links them again.

### The rotation checklist

The plan output repeats this, but in short:

- Register the new domain with WHOIS privacy, ideally under a separate registrar account.
- Never put old and new names on the same certificate. Prefer a wildcard certificate for the new domain, so individual hostnames stop appearing in CT.
- Don't redirect old hostnames to the new domain: a redirect hands the new domain to anyone who visits the old name.
- Delete the old DNS records after cutover. The old names stay in CT forever, but they should lead nowhere.
- Avoid OV/EV certificates that carry the same organisation name: crt.sh can be searched by organisation.
- Keep other identifiers separate where it matters: IP ranges, CDN account, analytics or tracking IDs, favicon.

**What a move can't undo:** an attacker who finds project A on the old domain will still see that project B's old names once existed there. The aim is that those names are dead ends with no path to B's new home.

## Command reference

Every command accepts the global options `--db PATH` (which database file to use) and `--version`. Run `crtwatch COMMAND -h` for details.

### Inventory

| Command | What it does |
|---|---|
| `crtwatch domain add NAME... [-f FILE] [--notes TEXT]` | Add domains. `-f` reads one domain per line; `#` starts a comment. |
| `crtwatch domain list` | Domains with host counts and last scan. |
| `crtwatch domain rm NAME...` | Remove domains and their hosts. |
| `crtwatch domain disable NAME...` / `enable` | Leave a domain out of "scan all" and scheduled scans, or put it back. |
| `crtwatch project add NAME [--rule PATTERN]... [--notes TEXT]` | Create a project, optionally with patterns. |
| `crtwatch project list` | Projects with their patterns, group and planned domain. |
| `crtwatch project rm NAME` | Delete a project. Its hosts become unassigned. |
| `crtwatch rule add PROJECT PATTERN...` / `rule rm` | Add or remove patterns. `rule add` creates the project if it doesn't exist. |
| `crtwatch assign PROJECT HOST...` | Assign exact hostnames (adds exact-name patterns). |
| `crtwatch ignore HOST... [--undo]` | Ignore hosts, or stop ignoring them. |
| `crtwatch import FILE.csv` | See [Importing a mapping from CSV](#importing-a-mapping-from-csv). |

### Scanning

| Command | What it does |
|---|---|
| `crtwatch scan [DOMAIN...] [--dns] [--every-source] [--workers N]` | Scan the given domains, or all enabled ones. Domains not yet in the inventory are added. `--dns` resolves every host afterwards. `--every-source` queries all certificate sources instead of stopping at the first that works. `--workers` sets how many domains run in parallel (default 2; crt.sh doesn't like more). |
| `crtwatch dns [DOMAIN...]` | Resolve hosts: `live`, `nxdomain`, `no_address`, `dangling` (CNAME to a target that doesn't exist) or `error`. |
| `crtwatch events [--limit N]` | New hosts and certificates found since each domain's baseline. |

### Analysis

| Command | What it does |
|---|---|
| `crtwatch hosts [--domain D] [--project P] [--unassigned] [-q TEXT] [--csv]` | List hosts. `--csv` produces a spreadsheet-friendly export. |
| `crtwatch report [--min-severity LEVEL] [--json]` | All findings, from critical down to info. |
| `crtwatch exposure [PROJECT]` | Blast radius for each project. |

### Separation and rotation

| Command | What it does |
|---|---|
| `crtwatch group GROUP PROJECT...` | Put projects in an exposure group. |
| `crtwatch group` | List groups and their members. |
| `crtwatch group --clear PROJECT...` | Remove projects from their group. |
| `crtwatch apart A B [--rm]` | Add (or remove) a pair rule. |
| `crtwatch keep DOMAIN [GROUP]` | Set the group that stays on a domain. Leave GROUP out to go back to automatic. |
| `crtwatch target PROJECT DOMAIN` / `target --group GROUP DOMAIN` | Record a planned domain. Use `-` as the domain to clear it. |
| `crtwatch check [--json]` | Violations, with paths. |
| `crtwatch plan [--json]` | Rotation plan, what would still be linked afterwards, and the checklist. |
| `crtwatch candidate DOMAIN...` | Vet new domains. Verdicts: `clean` (never had a certificate), `has_history` (has certificates; check who used it before), `linked` (a certificate already names it together with one of your domains). Also reports whether the domain is registered. |

### Running

| Command | What it does |
|---|---|
| `crtwatch serve [--host H] [--port P] [--every INTERVAL]` | Dashboard on 127.0.0.1:8080 by default. `--every 6h` also rescans in the background. Each tab has its own link, e.g. `http://127.0.0.1:8080/#separation`. |
| `crtwatch monitor [--every 6h] [--dns] [--workers N]` | Rescan forever without the dashboard. |
| `crtwatch --db demo.db demo` | Load the made-up *Acme* company into an empty database, to explore crtwatch without scanning. It refuses to touch a database that already has domains. |

Intervals accept `s`, `m`, `h` or `d`, e.g. `30m`, `6h` or `1d`.

## Importing a mapping from CSV

The first row must be a header. `project` and `pattern` are required; `group` and `domain` are optional.

```csv
project,pattern,group,domain
Shop,shop.acme.com,retail,acme.com
Shop,*.shop.acme.com,retail,
Payroll,payroll.acme.com,internal,
Partner Portal,partners.acme-ops.io,partners,acme-ops.io
```

- Each row adds one pattern to a project, creating the project if needed.
- `group` sets the project's exposure group.
- `domain` adds that domain to the inventory.

Importing again is safe: existing projects, patterns and domains are left as they are. `mapping.example.csv` is a starting point.

## Monitoring and alerts

Run either `crtwatch serve --every 6h` (dashboard plus scheduler) or `crtwatch monitor --every 6h --dns` (no dashboard). The Docker setup does the former.

After a domain's baseline, every scan records:

- `new_host`: a hostname under one of your domains appeared for the first time.
- `new_cert`: a certificate not seen before, with all its names.

These appear in the Activity tab and in `crtwatch events`. To get them as messages, set a webhook:

| Setting | Effect |
|---|---|
| `CRTWATCH_WEBHOOK_URL` | URL to POST to after each scan that found something new. |
| `CRTWATCH_WEBHOOK_FORMAT=slack` | `{"text": "..."}`, for Slack incoming webhooks (default). |
| `CRTWATCH_WEBHOOK_FORMAT=discord` | `{"content": "..."}`, for Discord webhooks. |
| `CRTWATCH_WEBHOOK_FORMAT=json` | `{"events": [...]}` with the raw event rows, for your own tooling. |

If a webhook delivery fails, it's retried after the next scan.

A new certificate that names hosts from two projects that must stay apart is the clearest warning sign. Run `crtwatch check` after an alert, or watch the Separation tab.

## Settings

All settings are environment variables. None are required.

| Variable | Default | Purpose |
|---|---|---|
| `CRTWATCH_DB` | `./data/crtwatch.db` | Database file. The `--db` option overrides it. |
| `CRTWATCH_PASSWORD` | none | Turns on HTTP basic auth for the dashboard and API. Required to listen on a non-local address. |
| `CRTWATCH_USER` | any | Also require this username for basic auth. |
| `CRTWATCH_ALLOW_NO_AUTH` | none | Set to `1` to listen on a public address without a password. Not recommended. |
| `CRTWATCH_DNS` | none | Set to `1` to run a DNS check after every dashboard or scheduled scan. |
| `CRTWATCH_RESOLVERS` | `1.1.1.1,8.8.8.8` | DNS resolvers for the DNS check and candidate vetting. |
| `CRTWATCH_WEBHOOK_URL`, `CRTWATCH_WEBHOOK_FORMAT` | none, `slack` | See [Monitoring and alerts](#monitoring-and-alerts). |
| `CERTSPOTTER_API_KEY` | none | Lifts CertSpotter's keyless rate limit. Only used when crt.sh is unavailable. |
| `CRTSH_DSN` | `host=crt.sh port=5432 dbname=certwatch user=guest` | Postgres connection string for the crt.sh replica, e.g. to go through a proxy. |

If [subfaster](https://github.com/melvinsh/subfaster) is installed and on your `PATH`, scans also use it to collect extra hostnames from non-CT passive sources.

## HTTP API

The dashboard is a thin layer over a JSON API on the same port. When `CRTWATCH_PASSWORD` is set, the API uses the same basic auth. Interactive docs are at `/api/docs`.

| Method and path | Purpose |
|---|---|
| `GET /api/summary` | Counts, findings, blast radius and violations. |
| `GET /api/export.json` | The same, as a downloadable file. |
| `GET /api/domains` | List domains. |
| `POST /api/domains` | Add domains. Body: `{"names": "a.com\nb.com", "scan": true}`. |
| `PATCH /api/domains/{name}` | Change `enabled`, `notes` or `keep_group`. |
| `DELETE /api/domains/{name}` | Remove a domain. |
| `POST /api/scan` | Queue scans. Body: `{"domains": [...], "dns": false}`; no domains = all enabled. |
| `POST /api/dns` | Queue a DNS check. |
| `GET /api/jobs` | Queue, current job, running scans with their current step, and recent results. |
| `GET /api/scans` | Scan history. |
| `GET /api/projects` | List projects. |
| `POST /api/projects` | Create a project. Body: `{"name": "...", "rules": [...]}`. |
| `PATCH /api/projects/{id}` | Change `name`, `notes`, `exposure_group` or `planned_domain`. |
| `DELETE /api/projects/{id}` | Delete a project. |
| `POST /api/projects/{id}/rules` | Add patterns. Body: `{"patterns": "a\nb"}`. |
| `DELETE /api/rules/{id}` | Remove a pattern. |
| `GET /api/hosts?domain=&project=&q=` | List hosts. Use `project=(unassigned)` for unmapped hosts. |
| `POST /api/hosts/assign` | Assign hosts. Body: `{"hosts": [...], "project_id": 3}`; `null` unassigns. |
| `POST /api/hosts/ignore` | Ignore hosts. Body: `{"hosts": [...], "ignored": true}`. |
| `GET /api/certs?host=` | Certificates for a host, with all their names. |
| `GET /api/events` | New hosts and certificates. |
| `GET /api/separation` | Groups, pair rules, violations, rotation plan, candidate checks and the checklist. |
| `POST /api/separations` | Add a pair rule. Body: `{"a": id, "b": id}`. |
| `DELETE /api/separations/{a}/{b}` | Remove a pair rule. |
| `POST /api/groups/target` | Set a group's planned domain. Body: `{"group": "...", "domain": "..."}`. |
| `POST /api/candidates` | Vet a domain. Body: `{"domain": "..."}`. Waits for the result, which can take up to a minute. |

## Troubleshooting

**A scan says `crtsh_pg failed`.** crt.sh's public database sometimes refuses connections when it's busy, and some networks block outgoing port 5432. crtwatch retries with backoff, then falls back to the crt.sh JSON API and then CertSpotter. The fallbacks work, but the JSON API only returns the names that match your domain, so links to other domains on the same certificate can be missed. Rescan later, or from a network that allows port 5432, for full results.

**`certificate verify failed`.** Some Python builds ship without a usable set of trusted certificate authorities. crtwatch uses the `certifi` bundle to avoid this; reinstall the package to make sure `certifi` is present.

**A big domain takes minutes.** That's normal for the first scan of a large domain. The banner shows which step it's on. Later scans take about as long, but only new items raise alerts.

**`refusing to listen on a public interface`.** Set `CRTWATCH_PASSWORD`, or keep the default `--host 127.0.0.1`.

**Everything is unassigned.** Patterns match whole hostnames. `shop.acme.com` doesn't match `www.shop.acme.com`; add `*.shop.acme.com` as well.

**A vendor's names show up as findings.** Shared CDN and hosting certificates (Cloudflare and others) are recognised and left out of the "domains you haven't added" list. If one still gets through, ignore those hosts.

**Where's my data?** In the file shown by `crtwatch -h` under `--db`. Delete that file to start over.
