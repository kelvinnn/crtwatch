# Changelog

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
