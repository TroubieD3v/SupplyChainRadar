# Security policy

## Supported versions
Only the latest `1.x` release receives fixes.

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub private vulnerability reporting (repository "Security" tab → "Report a vulnerability"). Include the affected version, a minimal reproducer (a crafted lockfile or SBOM is ideal) and the impact you observed. We aim to acknowledge reports within 7 days and to publish a fix or mitigation within 90 days; credit is given unless you prefer otherwise.

## Safe use
* The server is for local use. It binds to `127.0.0.1` by default; do not expose it to a network without TLS, authentication and `SCRADAR_API_TOKEN`.
* Imported files are treated as hostile data and parsed statically; nothing from them is executed. Add your own isolation (a throw-away VM or container) when you scan archives from sources you do not trust at all.
* Live OSV mode sends ecosystem, package name and version to `api.osv.dev`. Private package names would be disclosed; use offline or frozen-snapshot mode for private code.
* No telemetry is collected.

The full threat model is in [docs/threat-model.md](docs/threat-model.md).
