"""Shared helpers for the static, non-executing parsers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote

import yaml

from scradar import __version__
from scradar.domain.models import ROOT_ID, Component, DepType, Edge, Inventory, Location
from scradar.security import DEFAULT_LIMITS, Limits, redact

PARSER_VERSION = __version__


class IngestError(ValueError):
    """Input is malformed, unsupported or exceeds a safety limit."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_text(data: bytes, limits: Limits = DEFAULT_LIMITS) -> str:
    if len(data) > limits.max_file_bytes:
        raise IngestError(f"input is {len(data)} bytes, above the {limits.max_file_bytes} byte limit")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("input is not valid UTF-8 text") from exc


def load_json(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Any:
    text = decode_text(data, limits)
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise IngestError("JSON nesting is too deep") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that rejects anchors/aliases, closing YAML entity-expansion bombs."""

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            raise IngestError("YAML aliases are not accepted in lockfiles")
        return super().compose_node(parent, index)


def load_yaml(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Any:
    text = decode_text(data, limits)
    try:
        return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - SafeLoader subclass
    except IngestError:
        raise
    except RecursionError as exc:
        raise IngestError("YAML nesting is too deep") from exc
    except yaml.YAMLError as exc:
        raise IngestError(f"invalid YAML: {str(exc).splitlines()[0] if str(exc) else 'parse error'}") from exc


# --- identities -----------------------------------------------------------------------------

_PEP503 = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def make_id(ecosystem: str, name: str, version: str | None) -> str:
    return f"{ecosystem}:{name}@{version if version else 'unresolved'}"


def purl_npm(name: str, version: str | None) -> str:
    if name.startswith("@") and "/" in name:
        scope, rest = name.split("/", 1)
        base = f"pkg:npm/{quote(scope, safe='')}/{quote(rest, safe='')}"
    else:
        base = f"pkg:npm/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


def purl_pypi(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{quote(normalize_pypi_name(name), safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: dict[str, str]


def parse_purl(text: str) -> Purl | None:
    """Parse a Package URL; returns None when it is not a valid purl (never guesses)."""

    if not isinstance(text, str) or not text.startswith("pkg:"):
        return None
    body = text[4:].lstrip("/")
    body, _, _sub = body.partition("#")
    body, _, qual = body.partition("?")
    body, at, version = body.rpartition("@") if "@" in body else (body, "", "")
    parts = [unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    ptype = parts[0].lower()
    name = parts[-1]
    namespace = "/".join(parts[1:-1]) or None
    qualifiers = {}
    for item in qual.split("&") if qual else []:
        k, _, v = item.partition("=")
        if k:
            qualifiers[k] = unquote(v)
    if not name:
        return None
    return Purl(ptype, namespace, name, unquote(version) if at else None, qualifiers)


_PURL_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}


def purl_to_identity(p: Purl) -> tuple[str, str] | None:
    """Map a purl onto (OSV ecosystem, package name), or None for unmapped types."""

    eco = _PURL_ECOSYSTEMS.get(p.type)
    if not eco:
        return None
    if p.type == "npm":
        name = f"{p.namespace}/{p.name}" if p.namespace else p.name
    elif p.type == "pypi":
        name = normalize_pypi_name(p.name)
    elif p.type == "maven":
        name = f"{p.namespace}:{p.name}" if p.namespace else p.name
    elif p.type in {"golang", "composer"}:
        name = f"{p.namespace}/{p.name}" if p.namespace else p.name
    else:
        name = p.name
    return eco, name


def normalize_licenses(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out = [value]
    elif isinstance(value, dict):
        t = value.get("type") or value.get("name") or value.get("id")
        out = [str(t)] if t else []
    elif isinstance(value, list):
        for item in value:
            out.extend(normalize_licenses(item))
    return [s.strip()[:200] for s in out if isinstance(s, str) and s.strip()]


def line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# --- builder --------------------------------------------------------------------------------


class InventoryBuilder:
    """Collects components/edges while enforcing size ceilings and merging duplicates."""

    def __init__(
        self,
        *,
        format: str,
        parser: str,
        source_label: str,
        checksum: str,
        format_version: str | None = None,
        limits: Limits = DEFAULT_LIMITS,
    ) -> None:
        self.format = format
        self.parser = parser
        self.format_version = format_version
        self.source_label = redact(source_label) or source_label
        self.checksum = checksum
        self.limits = limits
        self.components: dict[str, Component] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self.warnings: list[str] = []
        self.graph_complete = True
        self.graph_note: str | None = None
        self.coverage: str = "full"
        self.coverage_notes: list[str] = []

    def warn(self, msg: str) -> None:
        msg = redact(msg) or msg
        if msg not in self.warnings and len(self.warnings) < 500:
            self.warnings.append(msg)

    def partial(self, note: str, *, graph: bool = False) -> None:
        self.coverage = "partial"
        if note not in self.coverage_notes:
            self.coverage_notes.append(note)
        if graph:
            self.graph_complete = False
            self.graph_note = self.graph_note or note

    def root(self, ecosystem: str, name: str, version: str | None = None) -> Component:
        comp = Component(
            id=ROOT_ID,
            kind="application",
            ecosystem=ecosystem,
            name=redact(name) or "application",
            version=version,
            resolved=True,
            source="application",
            scopes=["runtime"],
        )
        self.components[ROOT_ID] = comp
        return comp

    def add_component(self, comp: Component) -> Component:
        existing = self.components.get(comp.id)
        if existing is None:
            if len(self.components) >= self.limits.max_components:
                raise IngestError(f"component limit of {self.limits.max_components} exceeded")
            self.components[comp.id] = comp
            return comp
        for loc in comp.locations:
            if loc not in existing.locations:
                existing.locations.append(loc)
        for lic in comp.licenses:
            if lic not in existing.licenses:
                existing.licenses.append(lic)
        for t in comp.dep_types:
            if t not in existing.dep_types:
                existing.dep_types.append(t)
        for n in comp.notes:
            if n not in existing.notes:
                existing.notes.append(n)
        existing.purl = existing.purl or comp.purl
        existing.declared = existing.declared or comp.declared
        existing.repository = existing.repository or comp.repository
        existing.direct = existing.direct or comp.direct
        return existing

    def add_edge(
        self,
        parent: str,
        child: str,
        type: DepType = DepType.RUNTIME,
        *,
        constraint: str | None = None,
        provenance: Location | None = None,
        confidence: str = "declared",
    ) -> None:
        if parent == child:
            return
        key = (parent, child, type.value)
        if key in self.edges:
            return
        if len(self.edges) >= self.limits.max_edges:
            raise IngestError(f"edge limit of {self.limits.max_edges} exceeded")
        self.edges[key] = Edge(
            parent=parent,
            child=child,
            type=type,
            constraint=redact(constraint),
            provenance=provenance,
            confidence=confidence,  # type: ignore[arg-type]
        )

    def finish(self) -> Inventory:
        for e in self.edges.values():
            if e.parent == ROOT_ID and e.child in self.components:
                comp = self.components[e.child]
                comp.direct = True
                if e.constraint and not comp.declared:
                    comp.declared = e.constraint
        return Inventory(
            format=self.format,
            parser=self.parser,
            parser_version=PARSER_VERSION,
            format_version=self.format_version,
            source_label=self.source_label,
            checksum=self.checksum,
            components=self.components,
            edges=list(self.edges.values()),
            warnings=self.warnings,
            graph_complete=self.graph_complete,
            graph_note=self.graph_note,
            coverage=self.coverage,  # type: ignore[arg-type]
            coverage_notes=self.coverage_notes,
        )
