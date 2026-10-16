# 📙 How crtwatch works

This document explains what crtwatch does under the hood: where its data comes from, how it's stored, and how the findings, violations and rotation plan are worked out.

```
                  ┌──────────────── sources.py ────────────────┐
 crt.sh Postgres ─┤ crtsh_pg  (primary, full certificates)      │
 crt.sh JSON     ─┤ crtsh_json (fallback)                       │
 CertSpotter     ─┤ certspotter (fallback)                      ├─► scan.py ─► SQLite (db.py)
 Shodan CT       ─┤ shodanct  (extra names)                     │                 │
 subfaster       ─┤ subfaster (extra names, if installed)       │                 │
                  └─────────────────────────────────────────────┘                 ▼
                                    dnscheck.py ──► host DNS status    analyze.py: mapping, attacker walk, findings
                                    notify.py   ◄── new hosts/certs    separation.py: violations, rotation plan, vetting
                                                                                  │
                                                       cli.py (terminal)  ◄───────┴───────►  web.py + static/index.html (dashboard, API)
```

## Modules

| File | Role |
|---|---|
| `sources.py` | Talks to the CT sources and turns their answers into certificate records and hostnames. |
| `scan.py` | Runs one domain's scan: tries the sources, saves the results, records what's new, and reports progress. |
| `db.py` | SQLite schema, small migrations, and helpers. |
| `analyze.py` | Loads everything into memory, maps hosts to projects, walks the attacker pivots, and produces findings. |
| `separation.py` | Exposure groups and pair rules, violations, the rotation plan, and new-domain vetting. |
| `dnscheck.py` | Resolves hosts and detects dangling CNAMEs. |
| `probe.py` | The HTTP check: visits hosts, records status, redirects, title and a preview. The only module that connects to your servers. |
| `notify.py` | Sends new events to a webhook. |
| `cli.py` | The `crtwatch` command. |
| `demo.py` | The made-up *Acme* company loaded by `crtwatch demo`. |
| `web.py`, `static/index.html` | FastAPI app (JSON API, scan queue, scheduler) and the single-page dashboard. |

## 1. Collecting data

### Certificate sources

A scan of `acme.com` tries the certificate sources in order and stops at the first that answers:

1. **crt.sh Postgres** (`crtsh_pg`). crt.sh runs a public read-only replica of its database (`crt.sh:5432`, user `guest`). crtwatch finds every certificate with a name equal to `acme.com` or ending in `.acme.com`, then reads **all** the names on each of those certificates. It has no row limit and needs no key. Reading every name is what reveals cross-domain links.
2. **crt.sh JSON API** (`crtsh_json`). Used if the database is unreachable. It only returns the names that matched the search, so a certificate's other names, possibly on other domains, are missing.
3. **CertSpotter** (`certspotter`). Returns every name on each certificate, page by page. The keyless tier is rate-limited.

Each source call is retried with exponential backoff (5s, 10s, 20s) before the next source is tried. `--every-source` runs all three and merges the results.

### Name sources

After the certificate sources, **Shodan CT** and, if it's installed, **subfaster** add hostnames that aren't tied to a specific certificate. They make the inventory more complete, but they can't reveal links between names.

### Deduplication

crt.sh logs a *precertificate* and the final certificate separately, with the same issuer and serial number. crtwatch keys certificates by `issuer:serial`, so each certificate is counted once, with the union of the names on both copies. CertSpotter certificates are keyed by their TBS hash.

### What a scan saves

- Each **certificate**, with all its names, issuer and validity dates.
- A **certificate–name** link for every name on every certificate, whichever domain it belongs to.
- A **host** for every name that falls under *any* inventory domain. The host is attached to the longest matching inventory domain. So a scan of `acme.com` can discover a host of `acme-ops.io` through a shared certificate.
- A host's *first seen* date is the earliest validity start of any certificate that names it.
- Names under domains that aren't in the inventory are kept on their certificates but don't become hosts. They feed the "not in your inventory" finding.

### Baseline and events

The first scan of a domain is its baseline and raises no events. On later scans, a new certificate raises `new_cert` and a new host raises `new_host`. A host only raises an event if its own domain already has a baseline, so adding a new domain doesn't flood you with alerts. Events go to the webhook, if one is set.

### Progress

A scan updates its row in the `scans` table with its current step ("querying the crt.sh database", "trying CertSpotter", "saving 812 certificates"). The dashboard reads those rows, so it also shows scans started from the terminal. Scans still marked running after two hours are treated as abandoned. Inside the dashboard, scans go through a single queue processed by one worker thread, which keeps the load on crt.sh low.

## 2. Data model

```
domains ──< hosts            certs ──< cert_hosts >── (any hostname)
projects ──< rules           projects ──< separations >── projects
scans, events, candidates
```

| Table | Key columns |
|---|---|
| `domains` | `name`, `enabled`, `last_scan_at`, `last_scan_status`, `keep_group` |
| `hosts` | `name`, `domain_id`, `sources`, `first_seen_at`, `ignored`, `dns_status`, `dns_detail` |
| `certs` | `key`, `source`, `crtsh_id`, `issuer`, `not_before`, `not_after`, `sans` (JSON list) |
| `cert_hosts` | `cert_key`, `host`: one row per name on a certificate |
| `projects` | `name`, `exposure_group`, `planned_domain` |
| `rules` | `project_id`, `pattern` |
| `separations` | `project_a`, `project_b` (pair rules) |
| `scans` | `status` (`running`, `ok`, `partial`, `failed`, `interrupted`), `stage`, counts, `error` |
| `probes` | `host`, `status` (what the host itself answered), `final_status` (after redirects), `final_url`, `redirects` (JSON chain), `title`, `server`, `content_type`, `tls_error`, `snippet`, `html` (preview), `error` |
| `events` | `kind` (`new_host`, `new_cert`, `http_change`), `domain`, `subject`, `detail`, `notified` |
| `candidates` | `domain`, `verdict`, `detail` from new-domain vetting |

A scan is `partial` when only the name sources worked, so no certificate data came back. The schema is created on first run, and columns added in later versions are added automatically when an older database is opened.

## 3. Mapping hosts to projects

Each host is tested against every pattern with shell-style glob matching (`fnmatch`; `*` also matches dots). If several patterns match, the most specific wins: the one with the most literal (non-wildcard) characters, then the longest. An exact hostname therefore always beats a wildcard. Assigning a host in the dashboard simply adds an exact-name pattern.

Each host's **root** is its registrable domain, worked out with the public suffix list (bundled; no network needed). So `a.b.acme.co.uk` has the root `acme.co.uk`. The root is what an attacker searches crt.sh for.

## 4. The attacker walk

`analyze.walk()` simulates an attacker who starts from one project's hosts and keeps applying pivots until nothing new turns up. The two CT pivots are always used; a third is added once you've run the HTTP check:

```
frontier = the project's hosts
repeat:
    for each host in frontier:
        root pivot: if its root hasn't been searched yet, add every host under that root
        cert pivot: for each certificate naming the host not opened yet, add every name on it that is a known host
        redirect pivot: if the host's HTTP check redirected, add every known host the redirect chain passes through
    frontier = hosts added in this round   (one round = one hop)
```

Ignored hosts are skipped. For every host it reaches, the walk records the hop count, the pivot that found it, and the host it came from, so any result can be traced back step by step. All three pivots are available to anyone: crt.sh's search is public, every name on every logged certificate is public, and anyone can visit a hostname and see where it redirects.

**Blast radius** is the walk's result grouped by project: for each other project, how many of its hosts were reached, the fewest hops, and an example path.

## 5. Findings

| Finding | Severity | When |
|---|---|---|
| `cert_link` across roots | critical | One certificate names hosts of two or more projects on different root domains. Moving domains can't fix this; the names on that certificate are public forever. |
| `cert_link` | high | One certificate names hosts of two or more projects on the same root. |
| `shared_root` | high | Two or more projects have hosts under the same root. |
| `dangling_cname` | high | A host's CNAME points to a name that doesn't exist (subdomain takeover candidate). Needs a DNS check. |
| `redirect_link` to a planned domain | high | A host's redirect chain lands on a domain a project is planned to move to. This links old and new before the move has even happened. |
| `redirect_link` to your own domain | medium | A host redirects into another of your root domains. |
| `redirect_link` elsewhere | info | A host redirects to a domain not in the inventory. Often a login provider; sometimes a domain you forgot to add. |
| `cert_link` (roots only) | medium | One certificate ties several of your root domains together, revealing a common owner. |
| `unassigned_on_shared_root` | medium | Unassigned hosts next to mapped projects. |
| `unassigned` | low | Unassigned hosts on a root with no mapped projects. |
| `named_certs` | low | A project has 3 or more hostnames on certificates that are still valid. A wildcard certificate would stop new names leaking. |
| `foreign_root` | info | Domains you haven't added appear on certificates with your hosts. These are often your own forgotten domains. |

Certificates for links are grouped by the set of projects and roots they connect, with a count of how many are still valid. **Shared CDN and hosting certificates** are recognised in two ways: a certificate that names three or more roots you don't own, or that includes a known CDN or hosting domain (such as `cloudflaressl.com` or `fastly.net`). Their unrelated names are not reported as "your" domains, but if such a certificate names two of your projects, that link is still reported.

## 6. Separation

### Rules

Two projects **must stay apart** if:

- they have different, non-empty exposure groups, or
- a pair rule names them.

A project with no group and no pair rule is never checked.

### Violations

For every constrained project, crtwatch runs the walk and looks at the first host reached of each other project. If the two must stay apart, that's a violation. It's reported once per pair, keeping the shortest path. Each violation is labelled with its cause:

- **same root domain**: the two projects share a root, so one crt.sh search reveals both;
- **same certificate**: some certificate names hosts of both;
- **redirect**: a host of one redirects to a host of the other (from the HTTP check);
- **indirect**: neither, but a chain through other hosts connects them, for example A → shared root → unassigned host → shared certificate → B.

The full path is included, one pivot per step.

### Rotation plan

Projects are grouped into **units**: a whole exposure group, or a single project without a group. For every root that holds units which must stay apart:

1. **Choose who stays.** The domain's keep group if one is set; otherwise the unit that owns the apex or `www` host; otherwise the unit with the most hosts on that root.
2. **Sort the rest.** Go through the remaining units from most hosts to fewest. A unit stays if it doesn't conflict with anything already staying; otherwise it moves. This keeps as much as possible in place.
3. **Combine per unit.** A unit that has to leave several roots gets one entry listing each root it leaves, the number of hostnames there, and which of them still resolve (from the last DNS check). Those still-resolving names are the ones to decommission after cutover.
4. **Burned names.** For each moving unit, crtwatch finds old certificates that name the unit's hosts together with a unit it must stay apart from. Those pairings are permanent, so the names must never be reused.
5. **Check the planned domain.** It's flagged if its root already hosts a conflicting unit, if a conflicting unit is planned for the same root, if it hasn't been vetted yet, or if vetting found CT history (`has_history`) or a link to your domains (`linked`).
6. **Re-check afterwards.** crtwatch re-runs the violation check as if every moving unit had left its old roots (old names retired, new names on a fresh domain with their own certificates) and lists anything still linked, with a suggested fix. This catches links the moves don't fix, such as a pair rule between two projects in the same group, or a chain through a third root.

The plan works from what CT shows. It can't see links through shared IP addresses, page content, tracking IDs or registration records; the checklist covers those.

### Vetting a new domain

`check_candidate()` runs the same certificate sources for the proposed domain, without saving anything to the inventory, and reports:

- **linked**: a certificate names this domain together with one of your inventory domains, so an attacker can already follow it;
- **has_history**: certificates exist, but none link to you (common for domains bought second-hand);
- **clean**: no certificate has ever been logged.

It also looks up the domain's name servers. NXDOMAIN means the domain isn't registered. Results are saved in `candidates` and used by the plan's planned-domain checks.

## 7. HTTP check

`probe.py` visits each eligible host. Wildcards, ignored hosts, and (by default) names DNS says don't exist are skipped.

1. **Safety check.** The hostname is resolved first. If every address is private, loopback or link-local (`10.x`, `192.168.x`, `127.x`, `169.254.x`, …), the host is recorded as `skipped` and not contacted, unless private probing is enabled. The same check applies to every redirect target, so a public host can't bounce the checker into an internal service or a cloud metadata endpoint.
2. **Request.** `GET /` over `https://` with certificate verification. If verification fails, the error is recorded and the request is repeated without verification, so you still see what's there. If HTTPS fails entirely, `http://` is tried. A single request, an identifying user agent, an 8-second timeout, and at most 256 KB of body read.
3. **Redirects** are followed by hand, up to 5 hops, and every hop is recorded. `status` is what the hostname itself answered (e.g. `302`); `final_status` is what the chain ended on.
4. **Summary.** The page `<title>`; a text snippet of up to 600 characters, with head, script and style content removed and tags stripped; and, for successful HTML pages, the first 24 KB of markup for the preview.
5. **Change events.** If a host's result class (`2xx`, `3xx`, `4xx`, `5xx`, `down`) differs from the previous check, an `http_change` event is recorded and sent to the webhook.

Only the latest result per host is kept. 16 hosts are checked in parallel.

**Displaying results safely.** Page content comes from the outside world, so the dashboard treats it as untrusted. Titles and snippets are always shown as escaped text. The optional rendered preview goes in an `<iframe sandbox>` with no permissions, so scripts don't run and forms don't submit. A Content-Security-Policy of `default-src 'none'` means it can't load anything from the network either: no images, stylesheets or tracking pixels from the site, only inline styles.

## 8. DNS check

For each non-wildcard host, crtwatch looks up its CNAME, A and AAAA records using `CRTWATCH_RESOLVERS`:

| Status | Meaning |
|---|---|
| `live` | Resolves to an address. |
| `nxdomain` | The name doesn't exist (any more). |
| `no_address` | The name exists but has no A/AAAA record. |
| `dangling` | It's a CNAME, it has no address, and the CNAME target doesn't exist. |
| `error` | The resolvers timed out or failed. |

32 lookups run in parallel. Only public resolvers are contacted: the DNS check never connects to your servers (the HTTP check does).

## 9. Limits

- CT only shows names that appear on certificates. A host that has only ever been covered by a wildcard certificate is invisible here, and to attackers using CT.
- Attackers have other ways to link projects that crtwatch doesn't check yet: shared IP addresses and hosting, page or favicon fingerprints, analytics or tracking IDs, WHOIS records, and organisation names on OV/EV certificates. The HTTP check's titles, server headers and previews make some of these easy to spot by eye.
- The crt.sh database is a free community service. When it's overloaded, scans fall back to sources with less detail; see Troubleshooting in the [user guide](guide.md).
