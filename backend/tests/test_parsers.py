import json

import pytest

from scradar.domain.models import ROOT_ID, DepType
from scradar.graph.engine import DependencyGraph
from scradar.ingestion.common import IngestError, normalize_pypi_name, parse_purl, purl_npm
from scradar.ingestion.cyclonedx import parse_cyclonedx
from scradar.ingestion.detect import detect_kind, import_directory
from scradar.ingestion.npm import parse_npm_lock
from scradar.ingestion.pnpm import parse_pnpm_lock
from scradar.ingestion.poetry import parse_poetry_lock
from scradar.ingestion.requirements import parse_requirements
from scradar.ingestion.spdx import parse_spdx

from .conftest import EXAMPLES

# ------------------------------------------------------------------ npm


def test_npm_v3_example_graph():
    inv = parse_npm_lock((EXAMPLES / "npm-vulnerable" / "package-lock.json").read_bytes())
    assert inv.format_version == "3"
    assert inv.components[ROOT_ID].name == "demo-app"
    vl = inv.components["npm:demo-vulnerable-lib@1.2.0"]
    assert vl.purl == "pkg:npm/demo-vulnerable-lib@1.2.0"
    assert vl.locations[0].line is not None  # real line in the lockfile
    parents = {e.parent for e in inv.edges if e.child == vl.id}
    assert parents == {"npm:demo-framework-a@2.0.0", "npm:demo-framework-b@4.0.0"}
    dev = [e for e in inv.edges if e.parent == ROOT_ID and e.type == DepType.DEV]
    assert [e.child for e in dev] == ["npm:demo-test-runner@3.0.0"]


def _lock(packages, version=3):
    return json.dumps(
        {
            "name": "app",
            "lockfileVersion": version,
            "packages": {"": {"name": "app", "version": "1.0.0", **packages.pop("", {})}, **packages},
        }
    ).encode()


def test_npm_nested_resolution_and_scoped_alias():
    data = _lock(
        {
            "": {"dependencies": {"a": "^1.0.0", "@scope/b": "^2.0.0", "str-cjs": "npm:string-width@^4"}},
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                "dependencies": {"c": "^2.0.0"},
            },
            "node_modules/a/node_modules/c": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/c/-/c-2.0.0.tgz",
            },
            "node_modules/c": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz"},
            "node_modules/@scope/b": {
                "version": "2.1.0",
                "resolved": "https://registry.npmjs.org/@scope/b/-/b-2.1.0.tgz",
                "dependencies": {"c": "^1.0.0"},
            },
            "node_modules/str-cjs": {
                "name": "string-width",
                "version": "4.2.3",
                "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
            },
        }
    )
    inv = parse_npm_lock(data)
    edges = {(e.parent, e.child) for e in inv.edges}
    assert ("npm:a@1.0.0", "npm:c@2.0.0") in edges  # nested node_modules wins
    assert ("npm:@scope/b@2.1.0", "npm:c@1.0.0") in edges  # hoisted copy
    assert inv.components["npm:@scope/b@2.1.0"].purl == "pkg:npm/%40scope/b@2.1.0"
    alias = inv.components["npm:string-width@4.2.3"]  # real identity, not the alias
    assert any("alias" in n for n in alias.notes)


def test_npm_git_dependency_is_unsupported_for_lookup():
    data = _lock(
        {
            "": {"dependencies": {"g": "github:x/g"}},
            "node_modules/g": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/g.git#abc"},
        }
    )
    comp = parse_npm_lock(data).components["npm:g@1.0.0"]
    assert comp.source == "git" and comp.unsupported_reason and comp.purl is None


def test_npm_v2_supported_and_v1_rejected():
    data = _lock(
        {"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}},
        version=2,
    )
    assert parse_npm_lock(data).format_version == "2"
    with pytest.raises(IngestError, match="lockfileVersion"):
        parse_npm_lock(json.dumps({"lockfileVersion": 1, "dependencies": {}}).encode())


def test_npm_workspace_links():
    data = _lock(
        {
            "": {"workspaces": ["packages/*"]},
            "node_modules/lib": {"resolved": "packages/lib", "link": True},
            "packages/lib": {"name": "lib", "version": "0.1.0", "dependencies": {"a": "^1"}},
            "packages/web": {"name": "web", "version": "0.1.0", "dependencies": {"lib": "*"}},
            "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
        }
    )
    inv = parse_npm_lock(data)
    assert inv.components["npm-workspace:packages/lib"].source == "workspace"
    assert ("npm-workspace:packages/web", "npm-workspace:packages/lib") in {
        (e.parent, e.child) for e in inv.edges
    }


def test_npm_missing_dependency_marks_graph_partial():
    data = _lock({"": {"dependencies": {"ghost": "^1"}}})
    inv = parse_npm_lock(data)
    assert not inv.graph_complete and inv.coverage == "partial"


# ------------------------------------------------------------------ pnpm


def test_pnpm_v9_monorepo():
    inv = parse_pnpm_lock((EXAMPLES / "pnpm-monorepo" / "pnpm-lock.yaml").read_bytes())
    assert inv.format_version == "9.0"
    g = DependencyGraph(inv.components, inv.edges)
    paths = g.paths_to("npm:demo-vulnerable-lib@1.2.0")
    assert paths.total_found >= 3
    assert "npm:demo-framework-a@2.0.0" in inv.components  # peer variant merged
    assert any(e.type == DepType.WORKSPACE for e in inv.edges)


PNPM6 = b"""lockfileVersion: '6.0'

dependencies:
  left-pad:
    specifier: ^1.3.0
    version: 1.3.0
  '@scope/thing':
    specifier: ^2.0.0
    version: 2.0.0(react@18.2.0)

devDependencies:
  wcwidth:
    specifier: ^1.0.0
    version: 1.0.1

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-x}
    dev: false

  /@scope/thing@2.0.0(react@18.2.0):
    resolution: {integrity: sha512-y}
    dependencies:
      string-width-cjs: /string-width@4.2.3
    dev: false

  /string-width@4.2.3:
    resolution: {integrity: sha512-z}
    dev: false

  /wcwidth@1.0.1:
    resolution: {integrity: sha512-w}
    dev: true
"""


def test_pnpm_v6_single_project_with_alias():
    inv = parse_pnpm_lock(PNPM6)
    ids = set(inv.components)
    assert {
        "npm:left-pad@1.3.0",
        "npm:@scope/thing@2.0.0",
        "npm:string-width@4.2.3",
        "npm:wcwidth@1.0.1",
    } <= ids
    assert ("npm:@scope/thing@2.0.0", "npm:string-width@4.2.3") in {(e.parent, e.child) for e in inv.edges}
    dev = {e.child for e in inv.edges if e.parent == ROOT_ID and e.type == DepType.DEV}
    assert dev == {"npm:wcwidth@1.0.1"}


def test_pnpm_unsupported_version():
    with pytest.raises(IngestError, match="lockfileVersion"):
        parse_pnpm_lock(b"lockfileVersion: 5.4\n")


# ------------------------------------------------------------------ poetry


def test_poetry_with_pyproject_and_name_normalisation():
    d = EXAMPLES / "poetry-vulnerable"
    inv = parse_poetry_lock((d / "poetry.lock").read_bytes(), pyproject=(d / "pyproject.toml").read_bytes())
    assert inv.format_version == "2.1"
    edges = {(e.parent, e.child, e.type) for e in inv.edges}
    assert (
        "PyPI:demo-web@1.0.0",
        "PyPI:demo-templating@2.0.0",
        DepType.RUNTIME,
    ) in edges  # "Demo_Templating" normalised
    assert (ROOT_ID, "PyPI:demo-pytest@7.0.0", DepType.DEV) in edges
    assert inv.coverage == "full"


def test_poetry_without_pyproject_infers_roots_explicitly():
    inv = parse_poetry_lock((EXAMPLES / "poetry-vulnerable" / "poetry.lock").read_bytes())
    root_edges = [e for e in inv.edges if e.parent == ROOT_ID]
    assert root_edges and all(e.confidence == "inferred" for e in root_edges)
    assert inv.coverage == "partial"


POETRY_1 = b"""[[package]]
name = "requests"
version = "2.25.0"
description = ""
category = "main"
optional = false
python-versions = "*"

[package.dependencies]
urllib3 = ">=1.21.1,<1.27"
chardet = {version = ">=3.0.2,<5", optional = true}

[[package]]
name = "urllib3"
version = "1.26.5"
description = ""
category = "main"
optional = false
python-versions = "*"

[[package]]
name = "chardet"
version = "4.0.0"
description = ""
category = "main"
optional = true
python-versions = "*"

[metadata]
lock-version = "1.1"
python-versions = "^3.8"
content-hash = "abc"

[metadata.files]
requests = []
urllib3 = []
chardet = []
"""


def test_poetry_lock_v1_and_optional_edges():
    inv = parse_poetry_lock(POETRY_1)
    types = {(e.parent, e.child): e.type for e in inv.edges}
    assert types[("PyPI:requests@2.25.0", "PyPI:chardet@4.0.0")] == DepType.OPTIONAL
    assert types[("PyPI:requests@2.25.0", "PyPI:urllib3@1.26.5")] == DepType.RUNTIME


# ------------------------------------------------------------------ requirements


def test_requirements_partial_semantics_and_redaction():
    inv = parse_requirements((EXAMPLES / "requirements-partial" / "requirements.txt").read_bytes())
    c = inv.components
    assert c["PyPI:demo-flask@2.0.1"].resolved
    assert c["PyPI:demo-crypto@1.1.0"].resolved  # hash continuation line + name normalisation
    assert not c["PyPI:demo-requests@unresolved"].resolved
    assert not c["PyPI:demo-numpy@unresolved"].resolved
    assert c["PyPI:demo-local@unresolved"].source == "git"
    assert inv.coverage == "partial" and not inv.graph_complete
    blob = json.dumps(inv.model_dump(mode="json"))
    assert "not-a-real-password" not in blob and "ci-user" not in blob
    assert any("-r base.txt" in w for w in inv.warnings)


def test_requirements_line_numbers():
    inv = parse_requirements(b"# c\n\nfoo==1.0\nbar>=2\n")
    assert inv.components["PyPI:foo@1.0"].locations[0].line == 3


# ------------------------------------------------------------------ SBOM


@pytest.mark.parametrize("folder", ["sbom-cyclonedx", "sbom-cyclonedx-1.7"])
def test_cyclonedx_import(folder):
    inv = parse_cyclonedx((EXAMPLES / folder / "bom.cdx.json").read_bytes())
    assert inv.format_version in {"1.6", "1.7"}
    assert inv.graph_complete
    g = DependencyGraph(inv.components, inv.edges)
    assert g.paths_to("npm:demo-vulnerable-lib@1.2.0").total_found == 1


def test_cyclonedx_schema_violation_rejected():
    doc = json.loads((EXAMPLES / "sbom-cyclonedx" / "bom.cdx.json").read_text())
    doc["components"][0]["type"] = "not-a-type"
    with pytest.raises(IngestError, match="schema validation"):
        parse_cyclonedx(json.dumps(doc).encode())


def test_cyclonedx_without_dependencies_is_partial_not_manufactured():
    doc = json.loads((EXAMPLES / "sbom-cyclonedx" / "bom.cdx.json").read_text())
    del doc["dependencies"]
    doc["vulnerabilities"] = [{"id": "CVE-2099-0001"}]
    inv = parse_cyclonedx(json.dumps(doc).encode())
    assert not inv.graph_complete
    assert inv.edges == []
    assert any("never treated as confirmed" in w for w in inv.warnings)
    paths = DependencyGraph(inv.components, inv.edges).paths_to("npm:demo-parser@0.9.0")
    assert not paths.reachable_from_root and paths.warning


def test_cyclonedx_unsupported_spec():
    with pytest.raises(IngestError, match="specVersion"):
        parse_cyclonedx(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.2"}).encode())


SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "app",
    "dataLicense": "CC0-1.0",
    "documentDescribes": ["SPDXRef-app"],
    "packages": [
        {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0"},
        {
            "SPDXID": "SPDXRef-a",
            "name": "a",
            "versionInfo": "1.0.0",
            "licenseConcluded": "MIT",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/a@1.0.0",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-b",
            "name": "B_Pkg",
            "versionInfo": "2.0",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/B_Pkg@2.0",
                }
            ],
        },
        {"SPDXID": "SPDXRef-c", "name": "no-purl", "versionInfo": "1"},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a"},
        {
            "spdxElementId": "SPDXRef-b",
            "relationshipType": "DEV_DEPENDENCY_OF",
            "relatedSpdxElement": "SPDXRef-a",
        },
        {"spdxElementId": "SPDXRef-a", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-c"},
    ],
}


def test_spdx_relationships():
    inv = parse_spdx(json.dumps(SPDX).encode())
    edges = {(e.parent, e.child, e.type) for e in inv.edges}
    assert (ROOT_ID, "npm:a@1.0.0", DepType.RUNTIME) in edges
    assert ("npm:a@1.0.0", "PyPI:b-pkg@2.0", DepType.DEV) in edges
    assert inv.components["npm:a@1.0.0"].licenses == ["MIT"]
    assert any("CONTAINS" in w for w in inv.warnings)
    nopurl = next(c for c in inv.components.values() if c.name == "no-purl")
    assert nopurl.unsupported_reason


# ------------------------------------------------------------------ identities & detection


def test_identity_helpers():
    assert normalize_pypi_name("Demo_Templating.Extra") == "demo-templating-extra"
    assert purl_npm("@a/b", "1.0.0") == "pkg:npm/%40a/b@1.0.0"
    p = parse_purl("pkg:npm/%40a/b@1.0.0?x=1#sub")
    assert p and p.namespace == "@a" and p.name == "b" and p.version == "1.0.0" and p.qualifiers == {"x": "1"}
    assert parse_purl("not-a-purl") is None


def test_detection():
    assert detect_kind("package-lock.json") == "npm"
    assert detect_kind("requirements-dev.txt") == "requirements"
    assert detect_kind("bom.json", b'{"bomFormat":"CycloneDX"}') == "cyclonedx"
    assert detect_kind("x.spdx.json", b'{"spdxVersion":"SPDX-2.3"}') == "spdx"
    assert detect_kind("README.md") is None


def test_folder_import_merges_poetry_with_pyproject():
    out = import_directory(EXAMPLES / "poetry-vulnerable")
    assert len(out.inventories) == 1 and out.inventories[0].coverage == "full"
