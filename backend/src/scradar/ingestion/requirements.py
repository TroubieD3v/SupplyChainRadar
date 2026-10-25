"""requirements.txt: only exact pins (== / ===) are resolved; everything else stays unresolved."""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

from scradar.domain.models import ROOT_ID, Component, DepType, Inventory, Location
from scradar.ingestion.common import (
    IngestError,
    InventoryBuilder,
    decode_text,
    make_id,
    normalize_pypi_name,
    purl_pypi,
    sha256_hex,
)
from scradar.security import DEFAULT_LIMITS, Limits, redact, redact_str

_EGG = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")
_HASH_OPT = re.compile(r"\s+--hash[= ]\S+")
_COMMENT = re.compile(r"(^|\s)#.*$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def parse_requirements(
    data: bytes,
    source_label: str = "requirements.txt",
    limits: Limits = DEFAULT_LIMITS,
) -> Inventory:
    text = decode_text(data, limits)
    b = InventoryBuilder(
        format="requirements-txt",
        parser="scradar.ingestion.requirements",
        source_label=source_label,
        checksum=sha256_hex(data),
        limits=limits,
    )
    b.root("PyPI", "project", None)
    b.partial(
        "requirements.txt lists top-level requirements only; the transitive graph is not proven",
        graph=True,
    )
    seen = 0
    unresolved = 0
    for lineno, raw in _logical_lines(text):
        line = _COMMENT.sub("", raw).strip()
        if not line:
            continue
        loc = Location(file=b.source_label, line=lineno)
        if line.startswith("-"):
            _handle_option(b, line, lineno)
            continue
        line = _HASH_OPT.sub("", line).strip()
        egg = _EGG.search(line)
        if line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:", ".", "/")):
            name = normalize_pypi_name(egg.group(1)) if egg else None
            if name is None:
                b.warn(f"line {lineno}: VCS/URL/path requirement without an '#egg=' name was not resolved")
                unresolved += 1
                continue
            _add_unresolved(
                b,
                name,
                None,
                loc,
                "vcs-or-url requirement",
                source="git" if "+" in line.split(":")[0] else "url",
            )
            unresolved += 1
            seen += 1
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            b.warn(f"line {lineno}: could not parse requirement '{redact_str(line)[:80]}'")
            unresolved += 1
            continue
        name = normalize_pypi_name(req.name)
        seen += 1
        if req.url:
            _add_unresolved(b, name, None, loc, "direct URL reference (name @ url)", source="url")
            unresolved += 1
            continue
        specs = list(req.specifier)
        pinned = [s for s in specs if s.operator in {"==", "==="} and "*" not in s.version]
        marker = f"marker: {req.marker}" if req.marker else None
        if len(specs) == 1 and len(pinned) == 1:
            version = pinned[0].version
            comp = Component(
                id=make_id("PyPI", name, version),
                ecosystem="PyPI",
                name=name,
                version=version,
                purl=purl_pypi(name, version),
                declared=str(req.specifier),
                source="registry",
                locations=[loc],
                notes=[marker] if marker else [],
            )
            if req.extras:
                comp.notes.append("extras: " + ",".join(sorted(req.extras)))
            b.add_component(comp)
            b.add_edge(ROOT_ID, comp.id, DepType.RUNTIME, constraint=str(req.specifier), provenance=loc)
        else:
            constraint = str(req.specifier) or "(any version)"
            _add_unresolved(b, name, constraint, loc, f"not pinned to one exact version: {constraint}")
            unresolved += 1
    if seen == 0:
        raise IngestError("no requirements found in file")
    if unresolved:
        b.partial(
            f"{unresolved} requirement(s) are unpinned, ranged, local or VCS and cannot be matched to advisories"
        )
    return b.finish()


def _add_unresolved(
    b: InventoryBuilder,
    name: str,
    constraint: str | None,
    loc: Location,
    reason: str,
    source: str = "registry",
) -> None:
    comp = Component(
        id=make_id("PyPI", name, None),
        ecosystem="PyPI",
        name=name,
        version=None,
        declared=constraint,
        resolved=False,
        source=source,
        unsupported_reason=reason,
        locations=[loc],
    )
    merged = b.add_component(comp)
    b.add_edge(ROOT_ID, merged.id, DepType.RUNTIME, constraint=constraint, provenance=loc)


def _handle_option(b: InventoryBuilder, line: str, lineno: int) -> None:
    opt = line.split(None, 1)[0].split("=", 1)[0]
    arg = line[len(opt) :].lstrip(" =")
    if opt in {"-r", "--requirement", "-c", "--constraint"}:
        b.warn(f"line {lineno}: '{opt} {redact(arg)}' is not followed; import that file separately")
        b.partial("referenced requirement/constraint files were not followed", graph=True)
    elif opt in {"-e", "--editable"}:
        egg = _EGG.search(arg)
        if egg:
            name = normalize_pypi_name(egg.group(1))
            _add_unresolved(
                b,
                name,
                None,
                Location(file=b.source_label, line=lineno),
                "editable VCS/path requirement",
                "git",
            )
        else:
            b.warn(f"line {lineno}: editable install '{redact(arg)}' is a local project and is not resolved")
    elif opt in {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}:
        b.warn(
            f"line {lineno}: custom index/link source ({redact(arg)}); advisories assume the PyPI package of the same name"
        )
    else:
        b.warn(f"line {lineno}: pip option '{opt}' ignored")
