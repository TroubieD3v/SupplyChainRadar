import pytest

from scradar import versions
from scradar.versions import SemVer, VersionError, compare, npm_satisfies


def test_semver_prerelease_ordering():
    order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    parsed = [SemVer.parse(v) for v in order]
    assert parsed == sorted(parsed)


def test_pep440_is_not_semver():
    # 1.0.post1 is valid PEP 440 and newer than 1.0; not valid semver
    assert compare("PyPI", "1.0", "1.0.post1") == -1
    assert compare("PyPI", "2.0.0rc1", "2.0.0") == -1
    with pytest.raises(VersionError):
        compare("npm", "1.0.post1", "1.0.0")


def test_unknown_ecosystem_has_no_comparator():
    assert not versions.comparable("Maven")
    with pytest.raises(VersionError):
        compare("Maven", "1.0", "2.0")


@pytest.mark.parametrize(
    "version,rng,expected",
    [
        ("1.2.5", "^1.2.0", True),
        ("2.0.0", "^1.2.0", False),
        ("0.2.5", "^0.2.3", True),
        ("0.3.0", "^0.2.3", False),
        ("1.2.9", "~1.2.0", True),
        ("1.3.0", "~1.2.0", False),
        ("1.5.0", ">=1.0.0 <2.0.0", True),
        ("2.1.0", "1.x || >=2.1.0", True),
        ("1.4.0", "1.0.0 - 1.5.0", True),
        ("1.2.0", "1.2.0", True),
        ("1.2.1", "1.2.0", False),
        ("1.3.0-beta.1", "^1.2.0", False),
    ],
)
def test_npm_range(version, rng, expected):
    assert npm_satisfies(version, rng) is expected


def test_npm_range_unknown_syntax_is_none():
    assert npm_satisfies("1.0.0", "workspace:*") is None
    assert npm_satisfies("1.0.0", "github:user/repo") is None
