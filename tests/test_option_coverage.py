"""Every check option must have a behaviour test and be documented.

When you add, rename or remove an option, this file fails until OPTION_TESTS names a
test that proves the option changes what the check does, and the README lists it.
(Validation, example-config, list-checks --verbose and shell completion pick options
up automatically and are tested generically elsewhere.)
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from pydebuprep import checks

ROOT = Path(__file__).resolve().parent.parent

OPTION_TESTS: dict[tuple[str, str], str] = {
    ("apt-lists-age", "max_age_days"): "checks.test_apt_lists_age::test_max_age_configurable",
    (
        "boot-space",
        "warning_pct",
    ): "checks.test_kernel_boot::test_boot_space_thresholds_configurable",
    (
        "boot-space",
        "critical_pct",
    ): "checks.test_kernel_boot::test_boot_space_critical_threshold_configurable",
    (
        "config-conflicts",
        "critical_paths",
    ): "checks.test_config_and_debsums::test_config_conflicts_critical_paths_configurable",
    ("debsums", "timeout_seconds"): "checks.test_config_and_debsums::test_debsums_timeout_option",
    (
        "disk-space",
        "include_remote",
    ): "checks.test_storage::test_include_remote_checks_network_and_fuse_space",
    ("disk-space", "warning_pct"): "checks.test_storage::test_disk_space_thresholds_configurable",
    ("disk-space", "critical_pct"): "checks.test_storage::test_disk_space_thresholds_configurable",
    ("disk-space", "exclude_mounts"): "checks.test_storage::test_disk_space_exclude_mounts",
    ("dmesg-errors", "ignore"): "checks.test_services::test_dmesg_ignore_patterns",
    ("journal-errors", "ignore"): "checks.test_services::test_journal_ignore_patterns",
    ("systemd-failed", "ignore_units"): "checks.test_services::test_systemd_failed_ignore_units",
    ("systemd-timers", "ignore_units"): "checks.test_services::test_systemd_timers_ignore_units",
}

ALL_OPTIONS = sorted((cls.id, o.name) for cls in checks.ALL_CHECKS for o in cls.options)


def test_every_option_has_a_behaviour_test() -> None:
    missing = sorted(set(ALL_OPTIONS) - set(OPTION_TESTS))
    stale = sorted(set(OPTION_TESTS) - set(ALL_OPTIONS))
    assert not missing, f"options without a behaviour test in OPTION_TESTS: {missing}"
    assert not stale, f"OPTION_TESTS lists options that no longer exist: {stale}"


@pytest.mark.parametrize("key", sorted(OPTION_TESTS))
def test_named_test_exists(key: tuple[str, str]) -> None:
    module_name, _, func = OPTION_TESTS[key].partition("::")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, func, None)), f"{OPTION_TESTS[key]} not found"


@pytest.mark.parametrize("key", ALL_OPTIONS)
def test_option_documented_in_readme(key: tuple[str, str]) -> None:
    check_id, name = key
    rows = [line for line in (ROOT / "README.md").read_text().splitlines() if line.startswith("|")]
    assert any(f"`{check_id}`" in row and f"`{name}`" in row for row in rows), (
        f"README options table has no row for {check_id} listing `{name}`"
    )
