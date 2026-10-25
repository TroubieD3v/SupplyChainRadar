"""Ecosystem-specific version comparison.

There is deliberately no universal comparator: npm/Go/crates.io use SemVer 2.0 rules,
PyPI uses PEP 440. Ecosystems without a comparator report ``comparable() == False`` so
callers can mark range evaluation as *unsupported* instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

from packaging.version import InvalidVersion, Version


class VersionError(ValueError):
    """Raised when a version string cannot be parsed for its ecosystem."""


_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)(?:\.(?P<minor>0|[1-9]\d*))?(?:\.(?P<patch>0|[1-9]\d*))?"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> SemVer:
        m = _SEMVER_RE.match(text.strip())
        if not m:
            raise VersionError(f"not a semantic version: {text!r}")
        pre = tuple(m.group("pre").split(".")) if m.group("pre") else ()
        return cls(int(m.group("major")), int(m.group("minor") or 0), int(m.group("patch") or 0), pre)

    def _key(self) -> tuple:
        return (self.major, self.minor, self.patch)

    @staticmethod
    def _pre_cmp(a: tuple[str, ...], b: tuple[str, ...]) -> int:
        if not a and not b:
            return 0
        if not a:
            return 1  # a release outranks any pre-release
        if not b:
            return -1
        for x, y in zip(a, b, strict=False):
            xn, yn = x.isdigit(), y.isdigit()
            if xn and yn:
                if int(x) != int(y):
                    return -1 if int(x) < int(y) else 1
            elif xn != yn:
                return -1 if xn else 1  # numeric identifiers sort before alphanumeric
            elif x != y:
                return -1 if x < y else 1
        if len(a) == len(b):
            return 0
        return -1 if len(a) < len(b) else 1

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key() == other._key() and self.pre == other.pre

    def __lt__(self, other: SemVer) -> bool:
        if self._key() != other._key():
            return self._key() < other._key()
        return self._pre_cmp(self.pre, other.pre) < 0

    def __hash__(self) -> int:
        return hash((self._key(), self.pre))


_SEMVER_ECOSYSTEMS = {"npm", "go", "crates.io", "packagist", "nuget", "rubygems", "pub", "hex"}
_PEP440_ECOSYSTEMS = {"pypi"}


def comparable(ecosystem: str) -> bool:
    eco = ecosystem.lower()
    return eco in _SEMVER_ECOSYSTEMS or eco in _PEP440_ECOSYSTEMS


def parse(ecosystem: str, version: str):
    eco = ecosystem.lower()
    if eco in _PEP440_ECOSYSTEMS:
        try:
            return Version(version)
        except InvalidVersion as exc:
            raise VersionError(f"not a PEP 440 version: {version!r}") from exc
    if eco in _SEMVER_ECOSYSTEMS:
        return SemVer.parse(version)
    raise VersionError(f"no version comparator for ecosystem {ecosystem!r}")


def compare(ecosystem: str, a: str, b: str) -> int:
    pa, pb = parse(ecosystem, a), parse(ecosystem, b)
    return (pa > pb) - (pa < pb)


_NPM_CMP = re.compile(r"^(<=|>=|<|>|=)?\s*v?([0-9xX*]+(?:\.[0-9xX*]+){0,2}(?:-[0-9A-Za-z.-]+)?)$")


def _npm_partial(text: str) -> tuple[list[int | None], tuple[str, ...]]:
    core, _, pre = text.partition("-")
    nums: list[int | None] = []
    for part in core.split("."):
        nums.append(None if part in {"x", "X", "*"} else int(part))
    while len(nums) < 3:
        nums.append(None)
    return nums, tuple(pre.split(".")) if pre else ()


def _npm_comparators(token: str) -> list[tuple[str, SemVer]] | None:
    token = token.strip()
    if token in {"", "*", "x", "X", "latest"}:
        return []
    if token[0] in "^~":
        nums, pre = _npm_partial(token[1:].lstrip("v"))
        major, minor, patch = (n if n is not None else 0 for n in nums)
        low = SemVer(major, minor, patch, pre)
        if token[0] == "~":
            high = SemVer(major, minor + 1, 0) if nums[1] is not None else SemVer(major + 1, 0, 0)
        elif major > 0 or nums[1] is None:
            high = SemVer(major + 1, 0, 0)
        elif minor > 0 or nums[2] is None:
            high = SemVer(0, minor + 1, 0)
        else:
            high = SemVer(0, 0, patch + 1)
        return [(">=", low), ("<", high)]
    m = _NPM_CMP.match(token)
    if not m:
        return None
    op, ver = m.group(1) or "=", m.group(2)
    nums, pre = _npm_partial(ver)
    if None in nums:  # x-range: 1.x / 1.2.x
        if nums[0] is None:
            return []
        if nums[1] is None:
            lo, hi = SemVer(nums[0], 0, 0), SemVer(nums[0] + 1, 0, 0)
        else:
            lo, hi = SemVer(nums[0], nums[1], 0), SemVer(nums[0], nums[1] + 1, 0)
        if op == "=":
            return [(">=", lo), ("<", hi)]
        return [(op, lo if op in {">=", "<"} else hi)]
    return [(op, SemVer(nums[0] or 0, nums[1] or 0, nums[2] or 0, pre))]


def npm_satisfies(version: str, rng: str) -> bool | None:
    """Evaluate the common npm range grammar (^, ~, x-ranges, comparators, hyphen, ||).

    Returns None when the range uses syntax this evaluator does not understand
    (tags, URLs, workspace: protocol...), so callers can report "unknown" honestly.
    """

    try:
        v = SemVer.parse(version)
    except VersionError:
        return None
    if any(rng.startswith(p) for p in ("workspace:", "npm:", "file:", "git", "http", "link:")):
        return None
    for alt in rng.split("||"):
        alt = alt.strip()
        if " - " in alt:
            a, b = (s.strip() for s in alt.split(" - ", 1))
            comps = [(">=", SemVer.parse(a)), ("<=", SemVer.parse(b))]
        else:
            comps = []
            for tok in re.sub(r"(<=|>=|<|>|=)\s+", r"\1", alt).split():
                c = _npm_comparators(tok)
                if c is None:
                    return None
                comps.extend(c)
        ok = True
        for op, bound in comps:
            if not {"<": v < bound, "<=": v <= bound, ">": v > bound, ">=": v >= bound, "=": v == bound}[op]:
                ok = False
                break
        if ok and v.pre and not any(b.pre and b._key() == v._key() for _, b in comps):
            ok = False  # npm excludes prereleases unless a comparator opts in on the same tuple
        if ok:
            return True
    return False


def constraint_satisfied(ecosystem: str, version: str, constraint: str | None) -> bool | None:
    if not constraint:
        return None
    eco = ecosystem.lower()
    if eco == "npm":
        return npm_satisfies(version, constraint)
    if eco == "pypi":
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        try:
            return Version(version) in SpecifierSet(constraint)
        except (InvalidSpecifier, InvalidVersion):
            return None
    return None


def sort_key(ecosystem: str):
    """Return a key function for sorting versions; raises VersionError on bad input."""

    return lambda v: parse(ecosystem, v)
