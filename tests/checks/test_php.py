"""php: extensions enabled before the upgrade, per SAPI, across PHP versions."""

from __future__ import annotations

from typing import Any

import pytest

from checks.helpers import make_ctx, titles
from pydebuprep.checks.base import CheckSkipped
from pydebuprep.checks.php import PhpCheck, enabled_extensions
from pydebuprep.model import Severity


def php_files(version: str, sapis: dict[str, list[str]]) -> dict[str, str]:
    files = {}
    for sapi, extensions in sapis.items():
        for n, ext in enumerate(extensions):
            files[f"/etc/php/{version}/{sapi}/conf.d/{10 + n}-{ext}.ini"] = (
                f"; priority=20\nextension={ext}.so\n"
            )
    return files


BEFORE = {"7.4": {"fpm": ["intl", "json", "mysqli", "opcache"], "cli": ["json", "mysqli"]}}


def test_skipped_without_php() -> None:
    with pytest.raises(CheckSkipped, match="PHP is not installed"):
        PhpCheck().run(make_ctx())
    assert PhpCheck().collect_baseline(make_ctx()) is None


def test_run_finds_nothing_by_itself() -> None:
    assert PhpCheck().run(make_ctx(files=php_files("8.2", {"cli": ["mysqli"]}))) == []


def test_enabled_extensions_reads_every_sapi() -> None:
    files = {
        **php_files("7.4", {"fpm": ["mysqli"]}),
        **php_files("8.2", {"apache2": ["intl"], "cli": ["intl"]}),
        "/etc/php/8.2/cli/conf.d/99-commented.ini": ";extension=gd\n",
        "/etc/php/8.2/cli/conf.d/README": "extension=nope\n",
        "/etc/php/8.2/mods-available/gd.ini": "extension=gd\n",
        "/etc/php/latest/cli/conf.d/x.ini": "extension=x\n",
    }
    assert enabled_extensions(make_ctx(files=files)) == {
        "7.4": {"fpm": ["mysqli"]},
        "8.2": {"apache2": ["intl"], "cli": ["intl"]},
    }


def test_zend_extension_and_paths() -> None:
    files = {
        "/etc/php/8.2/fpm/conf.d/10-opcache.ini": "zend_extension=/usr/lib/php/20220829/opcache.so\n",
        "/etc/php/8.2/fpm/conf.d/20-redis.ini": 'extension = "redis"\n',
    }
    assert enabled_extensions(make_ctx(files=files)) == {"8.2": {"fpm": ["opcache", "redis"]}}


def test_upgrade_with_all_extensions_is_clean() -> None:
    files = php_files("8.2", {"fpm": ["intl", "mysqli", "opcache"], "cli": ["mysqli"]})
    assert PhpCheck().compare(make_ctx(files=files), BEFORE) == []


def test_missing_extension_after_version_change() -> None:
    files = php_files("8.2", {"fpm": ["opcache"], "cli": ["mysqli"]})
    [finding] = PhpCheck().compare(make_ctx(files=files), BEFORE)
    assert (finding.severity, finding.title) == (
        Severity.WARNING,
        "PHP extensions enabled before the upgrade aren't enabled now",
    )
    assert finding.evidence == ["fpm: intl, mysqli (enabled for PHP 7.4)"]
    assert "sudo apt install php8.2-intl php8.2-mysql" in finding.remediation


def test_json_built_in_since_8() -> None:
    # json has no ini file from PHP 8.0 on: it's part of PHP itself.
    files = php_files("8.2", {"fpm": ["intl", "mysqli", "opcache"], "cli": ["mysqli"]})
    assert PhpCheck().compare(make_ctx(files=files), BEFORE) == []
    still_7 = php_files("7.4", {"fpm": ["intl", "mysqli", "opcache"], "cli": ["mysqli"]})
    [finding] = PhpCheck().compare(make_ctx(files=still_7), BEFORE)
    assert finding.evidence == [
        "cli: json (enabled for PHP 7.4)",
        "fpm: json (enabled for PHP 7.4)",
    ]


def test_sapi_gone() -> None:
    files = php_files("8.2", {"cli": ["mysqli"]})
    found = PhpCheck().compare(make_ctx(files=files), BEFORE)
    assert titles(found) == ["PHP fpm is no longer installed for any PHP version"]
    assert found[0].severity is Severity.WARNING
    assert "sudo apt install php-fpm" in found[0].remediation


@pytest.mark.parametrize(
    "before",
    [
        None,
        [],
        "x",
        {"7.4": "fpm"},
        {"7.4": {"fpm": "intl"}},
        {"7.4": {"fpm": [1, None]}},
        {"x": {"bogus": ["intl"]}},
    ],
)
def test_malformed_baseline_ignored(before: Any) -> None:
    assert PhpCheck().compare(make_ctx(files=php_files("8.2", {"cli": []})), before) == []


def test_collect_baseline_round_trip() -> None:
    ctx = make_ctx(files=php_files("7.4", BEFORE["7.4"]))
    baseline = PhpCheck().collect_baseline(ctx)
    assert baseline == BEFORE
    assert PhpCheck().compare(ctx, baseline) == []
