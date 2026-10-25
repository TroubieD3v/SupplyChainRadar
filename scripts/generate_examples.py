"""Generate the committed demo projects and frozen advisory snapshots.

Everything here is SYNTHETIC. Package names start with ``demo-`` and advisory ids with
``DEMO-``; none of them describe a real package or a real vulnerability.
Run:  python scripts/generate_examples.py
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REG = "https://registry.npmjs.org"


def integ(name: str, version: str) -> str:
    return "sha512-" + hashlib.sha512(f"{name}@{version}".encode()).hexdigest()[:86] + "=="


def entry(name: str, version: str, deps: dict | None = None, **extra) -> dict:
    e = {
        "version": version,
        "resolved": f"{REG}/{name}/-/{name}-{version}.tgz",
        "integrity": integ(name, version),
        "license": extra.pop("license", "MIT"),
    }
    if deps:
        e["dependencies"] = deps
    e.update(extra)
    return e


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def npm_lock(app: str, deps: dict, dev: dict, pkgs: dict[str, dict]) -> dict:
    root = {"name": app, "version": "1.0.0", "license": "UNLICENSED", "dependencies": deps}
    if dev:
        root["devDependencies"] = dev
    return {
        "name": app,
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": root, **pkgs},
    }


# ---------------------------------------------------------------- npm-vulnerable / remediated
def build_npm(remediated: bool) -> dict:
    vl = "1.2.5" if remediated else "1.2.0"
    fa = "2.1.0" if remediated else "2.0.0"
    parser = "0.9.3" if remediated else "0.9.0"
    http = "1.5.0" if remediated else "1.4.0"
    http_deps = {"demo-parser": f"^{parser}"}
    if remediated:
        http_deps["demo-newdep"] = "^2.0.0"
    pkgs = {
        "node_modules/demo-framework-a": entry(
            "demo-framework-a", fa, {"demo-vulnerable-lib": f"^{vl}", "demo-util": "^1.0.0"}
        ),
        "node_modules/demo-framework-b": entry("demo-framework-b", "4.0.0", {"demo-vulnerable-lib": "^1.2.0"}),
        "node_modules/demo-vulnerable-lib": entry("demo-vulnerable-lib", vl),
        "node_modules/demo-util": entry("demo-util", "1.0.0", {"demo-core": "^1.0.0"}),
        # demo-core <-> demo-util is a deliberate dependency cycle
        "node_modules/demo-core": entry("demo-core", "1.0.0", {"demo-util": "^1.0.0"}),
        "node_modules/demo-http": entry("demo-http", http, http_deps),
        "node_modules/demo-parser": entry("demo-parser", parser),
        "node_modules/demo-test-runner": entry("demo-test-runner", "3.0.0", {"demo-glob": "^7.0.0"}, dev=True),
        "node_modules/demo-glob": entry("demo-glob", "7.0.0", dev=True, license="ISC"),
    }
    if remediated:
        pkgs["node_modules/demo-newdep"] = entry("demo-newdep", "2.0.0")
    return npm_lock(
        "demo-app",
        {"demo-framework-a": f"^{fa}", "demo-framework-b": "^4.0.0", "demo-http": f"^{http}"},
        {"demo-test-runner": "^3.0.0"},
        pkgs,
    )


def build_npm_clean() -> dict:
    pkgs = {
        "node_modules/demo-safe-a": entry("demo-safe-a", "3.1.0", {"demo-safe-b": "^1.0.0"}),
        "node_modules/demo-safe-b": entry("demo-safe-b", "1.0.4"),
    }
    return npm_lock("demo-clean-app", {"demo-safe-a": "^3.1.0"}, {}, pkgs)


# ---------------------------------------------------------------- pnpm monorepo (v9)
PNPM = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    devDependencies:
      demo-test-runner:
        specifier: ^3.0.0
        version: 3.0.0

  packages/api:
    dependencies:
      demo-framework-b:
        specifier: ^4.0.0
        version: 4.0.0
      demo-shared:
        specifier: workspace:*
        version: link:../shared

  packages/shared:
    dependencies:
      demo-vulnerable-lib:
        specifier: ^1.2.0
        version: 1.2.0

  packages/web:
    dependencies:
      demo-framework-a:
        specifier: ^2.0.0
        version: 2.0.0(demo-react@18.2.0)
      demo-react:
        specifier: ^18.2.0
        version: 18.2.0
      demo-shared:
        specifier: workspace:*
        version: link:../shared

packages:

  demo-framework-a@2.0.0:
    resolution: {integrity: sha512-aaa}
    peerDependencies:
      demo-react: ^18.0.0

  demo-framework-b@4.0.0:
    resolution: {integrity: sha512-bbb}

  demo-glob@7.0.0:
    resolution: {integrity: sha512-ccc}

  demo-react@18.2.0:
    resolution: {integrity: sha512-ddd}

  demo-test-runner@3.0.0:
    resolution: {integrity: sha512-eee}

  demo-vulnerable-lib@1.2.0:
    resolution: {integrity: sha512-fff}

snapshots:

  demo-framework-a@2.0.0(demo-react@18.2.0):
    dependencies:
      demo-react: 18.2.0
      demo-vulnerable-lib: 1.2.0

  demo-framework-b@4.0.0:
    dependencies:
      demo-vulnerable-lib: 1.2.0

  demo-glob@7.0.0: {}

  demo-react@18.2.0: {}

  demo-test-runner@3.0.0:
    dependencies:
      demo-glob: 7.0.0

  demo-vulnerable-lib@1.2.0: {}
"""


# ---------------------------------------------------------------- poetry
def poetry_pkg(name: str, version: str, deps: dict[str, str] | None = None, groups=("main",)) -> str:
    quoted = ", ".join(f'"{g}"' for g in groups)
    out = (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        f'description = "Synthetic demo package"\noptional = false\n'
        f'python-versions = ">=3.9"\ngroups = [{quoted}]\nfiles = []\n'
    )
    if deps:
        out += "\n[package.dependencies]\n" + "".join(f'{k} = "{v}"\n' for k, v in deps.items())
    return out + "\n"


POETRY_LOCK = (
    "# This file is automatically @generated by Poetry 2.1.0 and should not be changed by hand.\n\n"
    + poetry_pkg("demo-web", "1.0.0", {"Demo_Templating": ">=2.0", "demo-crypto": "^1.1"})
    + poetry_pkg("demo-templating", "2.0.0")
    + poetry_pkg("demo-crypto", "1.1.0")
    + poetry_pkg("demo-pytest", "7.0.0", None, groups=("dev",))
    + '[metadata]\nlock-version = "2.1"\npython-versions = ">=3.9,<4.0"\n'
    + 'content-hash = "0000000000000000000000000000000000000000000000000000000000000000"\n'
)

PYPROJECT = """[tool.poetry]
name = "demo-poetry-app"
version = "1.0.0"
description = "Synthetic Poetry demo"
authors = ["Demo <demo@example.invalid>"]

[tool.poetry.dependencies]
python = "^3.9"
demo-web = "^1.0"

[tool.poetry.group.dev.dependencies]
demo-pytest = "^7.0"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
"""

REQUIREMENTS = """# Partial coverage demo: only exact pins can be matched to advisories.
demo-flask==2.0.1
demo-requests>=2.0
demo-numpy
demo-pandas==1.0.0 ; python_version < "3.9"
Demo_Crypto==1.1.0 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
-r base.txt
-e git+https://github.com/example/demo-local.git#egg=demo-local
--extra-index-url https://ci-user:not-a-real-password@packages.example.invalid/simple
"""


# ---------------------------------------------------------------- CycloneDX
def cdx(spec: str) -> dict:
    def c(name, ver, scope="required"):
        return {
            "type": "library",
            "bom-ref": f"pkg:npm/{name}@{ver}",
            "name": name,
            "version": ver,
            "purl": f"pkg:npm/{name}@{ver}",
            "scope": scope,
            "licenses": [{"license": {"id": "MIT"}}],
        }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T00:00:00Z",
            "component": {"type": "application", "bom-ref": "demo-sbom-app", "name": "demo-sbom-app", "version": "1.0.0"},
        },
        "components": [
            c("demo-framework-a", "2.0.0"),
            c("demo-vulnerable-lib", "1.2.0"),
            c("demo-parser", "0.9.0"),
            c("demo-http", "1.4.0"),
        ],
        "dependencies": [
            {"ref": "demo-sbom-app", "dependsOn": ["pkg:npm/demo-framework-a@2.0.0", "pkg:npm/demo-http@1.4.0"]},
            {"ref": "pkg:npm/demo-framework-a@2.0.0", "dependsOn": ["pkg:npm/demo-vulnerable-lib@1.2.0"]},
            {"ref": "pkg:npm/demo-http@1.4.0", "dependsOn": ["pkg:npm/demo-parser@0.9.0"]},
            {"ref": "pkg:npm/demo-vulnerable-lib@1.2.0", "dependsOn": []},
            {"ref": "pkg:npm/demo-parser@0.9.0", "dependsOn": []},
        ],
    }


# ---------------------------------------------------------------- advisories
def adv(
    id_, aliases, eco, name, events, summary, *, vector=None, label=None, versions=None,
    published="2026-06-01T00:00:00Z", modified="2026-06-02T00:00:00Z", rtype="SEMVER",
):
    affected = {
        "package": {"ecosystem": eco, "name": name},
        "ranges": [{"type": rtype, "events": events}],
    }
    if versions:
        affected["versions"] = versions
    rec = {
        "schema_version": "1.6.0",
        "id": id_,
        "aliases": aliases,
        "summary": summary,
        "details": (
            f"{summary}. SYNTHETIC demo advisory shipped with SupplyChain Radar test fixtures; "
            "it does not describe a real package."
        ),
        "published": published,
        "modified": modified,
        "affected": [affected],
        "references": [
            {"type": "ADVISORY", "url": f"https://example.invalid/advisories/{id_}"},
            {"type": "FIX", "url": f"https://example.invalid/{name}/releases"},
        ],
    }
    if vector:
        rec["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if label:
        rec["database_specific"] = {"severity": label}
    return rec


SNAP1 = [
    adv("DEMO-GHSA-0001", ["DEMO-CVE-2026-0001"], "npm", "demo-vulnerable-lib",
        [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}], "Prototype handling flaw in demo-vulnerable-lib",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    adv("DEMO-OSV-0001", ["DEMO-CVE-2026-0001"], "npm", "demo-vulnerable-lib",
        [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}],
        "Same issue republished by a second database (alias duplicate)", label="HIGH"),
    adv("DEMO-GHSA-0002", ["DEMO-CVE-2026-0002"], "npm", "demo-parser",
        [{"introduced": "0"}, {"fixed": "0.9.3"}], "Input validation weakness in demo-parser",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    adv("DEMO-GHSA-0003", ["DEMO-CVE-2026-0003"], "npm", "demo-glob",
        [{"introduced": "0"}, {"fixed": "7.2.0"}], "Pattern expansion issue in demo-glob (dev-only in the demo apps)",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", versions=["7.0.0", "7.1.0"]),
    adv("DEMO-GHSA-0004", ["DEMO-CVE-2026-0004"], "npm", "demo-newdep",
        [{"introduced": "0"}, {"fixed": "2.0.1"}], "Deserialisation issue in demo-newdep",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    adv("DEMO-PYSEC-0005", ["DEMO-CVE-2026-0005"], "PyPI", "demo-templating",
        [{"introduced": "0"}, {"fixed": "2.0.5"}], "Template sandbox escape in demo-templating",
        label="HIGH", rtype="ECOSYSTEM"),
    adv("DEMO-PYSEC-0006", [], "PyPI", "demo-flask",
        [{"introduced": "2.0.0"}, {"fixed": "2.0.3"}],
        "Session handling issue in demo-flask (source gives no severity)", rtype="ECOSYSTEM"),
    adv("DEMO-PYSEC-0007", ["DEMO-CVE-2026-0007"], "PyPI", "demo-crypto",
        [{"introduced": "0"}, {"last_affected": "1.1.0"}], "Weak default in demo-crypto up to and including 1.1.0",
        vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", rtype="ECOSYSTEM"),
]

SNAP2 = copy.deepcopy(SNAP1)
# 1) a vulnerability disclosed after snapshot 1 for a package that has not changed
SNAP2.append(
    adv("DEMO-GHSA-0009", ["DEMO-CVE-2026-0009"], "npm", "demo-http",
        [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}], "Header parsing issue in demo-http (disclosed after snapshot 1)",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        published="2026-10-18T00:00:00Z", modified="2026-10-18T00:00:00Z")
)
# 2) a severity reclassification of an existing advisory
for _rec in SNAP2:
    if _rec["id"] == "DEMO-GHSA-0002":
        _rec["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
        _rec["modified"] = "2026-10-19T00:00:00Z"


def snapshot(sid: str, generated: str, records: list) -> dict:
    return {
        "schema_version": 1,
        "snapshot_id": sid,
        "generated": generated,
        "synthetic": True,
        "description": "Synthetic frozen advisory snapshot for offline tests and demos. Not real vulnerability data.",
        "ecosystems": ["npm", "PyPI"],
        "advisories": records,
    }


def dump(d) -> str:
    return json.dumps(d, indent=2) + "\n"


def main() -> None:
    ex = ROOT / "examples"
    write(ex / "npm-vulnerable" / "package-lock.json", dump(build_npm(False)))
    write(ex / "npm-remediated" / "package-lock.json", dump(build_npm(True)))
    write(ex / "npm-clean" / "package-lock.json", dump(build_npm_clean()))
    write(ex / "pnpm-monorepo" / "pnpm-lock.yaml", PNPM)
    write(ex / "poetry-vulnerable" / "poetry.lock", POETRY_LOCK)
    write(ex / "poetry-vulnerable" / "pyproject.toml", PYPROJECT)
    write(ex / "requirements-partial" / "requirements.txt", REQUIREMENTS)
    write(ex / "sbom-cyclonedx" / "bom.cdx.json", dump(cdx("1.6")))
    write(ex / "sbom-cyclonedx-1.7" / "bom.cdx.json", dump(cdx("1.7")))
    fx = ROOT / "fixtures" / "osv"
    write(fx / "frozen-advisories.json", dump(snapshot("demo-2026-10-01", "2026-10-01T00:00:00Z", SNAP1)))
    write(fx / "frozen-advisories-later.json", dump(snapshot("demo-2026-10-20", "2026-10-20T00:00:00Z", SNAP2)))
    print("examples and fixtures written")


if __name__ == "__main__":
    main()
