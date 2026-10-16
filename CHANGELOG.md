# Changelog

## 1.1.0

- **HTTP check** (`crtwatch probe`, or the *HTTP check* button): visits each host and records its status code, redirect chain, page title, server, certificate problems and a text preview. Private and internal addresses are skipped unless allowed.
- Hosts table: colour-coded status pills with titles and redirect targets, and an HTTP filter. Host details: an HTTP card with a sandboxed rendered preview (no scripts, no network).
- Redirects are now an attacker pivot: they count towards blast radius and separation violations (new cause: *redirect*). New finding for redirects that cross domains, rated high when they reveal a planned new domain.
- `http_change` alerts when a host's HTTP result changes between checks. `CRTWATCH_PROBE=1` runs the check after scheduled scans.
- Direct links to a host's details (`/#host=NAME`), and tab links now work without reloading.

## 1.0.0

First release.

- Certificate Transparency scanning via crt.sh's Postgres database (full certificates, no row limit), with crt.sh JSON and CertSpotter as fallbacks, and Shodan CT / subfaster for extra names.
- Projects mapped by hostname patterns; findings for shared domains, shared certificates, unassigned hosts, dangling CNAMEs and unadded domains.
- Attacker walk (root and certificate pivots) with per-project blast radius.
- Exposure groups and pair rules, violations with step-by-step paths, a domain rotation plan with burned-name detection, and new-domain vetting.
- Proprietary, internal-use licence notice (LICENSE).
- `crtwatch demo` loads a made-up company to explore without scanning; every dashboard tab has its own link.
- Beginner guide with screenshots (docs/getting-started.md), full reference (docs/guide.md) and internals (docs/how-it-works.md).
- Web dashboard with scan progress and a scan queue, command line, JSON API, scheduled rescans, webhook alerts, Docker setup.
