"""Every check option must have a behaviour test and be documented.

When you add, rename or remove an option, this file fails until OPTION_TESTS names a
test that proves the option changes what the check does, and the README lists it.
(Validation, example-config, list-checks --verbose and shell completion pick options
up automatically and are tested generically elsewhere.)
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pydebuprep import checks

ROOT = Path(__file__).resolve().parent.parent

OPTION_TESTS: dict[tuple[str, str], str] = {
    ("python-venvs", "exclude_paths"): "checks.test_applications::test_venvs_in_caches_are_skipped",
    (
        "python-venvs",
        "search_paths",
    ): "checks.test_applications::test_venvs_search_paths_and_depth_options",
    (
        "python-venvs",
        "max_depth",
    ): "checks.test_applications::test_venvs_search_paths_and_depth_options",
    (
        "network",
        "ignore_interfaces",
    ): "checks.test_network_time::test_network_ignore_interfaces_option",
    (
        "disk-space",
        "important_mounts",
    ): "checks.test_storage::test_important_mounts_warning_band_and_options",
    (
        "disk-space",
        "min_free_mib",
    ): "checks.test_storage::test_important_mounts_warning_band_and_options",
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
    (
        "config-conflicts",
        "ignore_paths",
    ): "checks.test_config_and_debsums::test_config_conflicts_ignore_paths",
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
    (
        "systemd-critical-services",
        "required_active",
    ): "checks.test_systemd_critical::test_configured_lists_are_separate",
    (
        "systemd-critical-services",
        "required_enabled",
    ): "checks.test_systemd_critical::test_configured_lists_are_separate",
    (
        "systemd-critical-services",
        "builtin",
    ): "checks.test_systemd_critical::test_builtin_false_and_ignore_units",
    (
        "systemd-critical-services",
        "ignore_units",
    ): "checks.test_systemd_critical::test_builtin_false_and_ignore_units",
    ("systemd-failed", "ignore_units"): "checks.test_services::test_systemd_failed_ignore_units",
    ("systemd-timers", "ignore_units"): "checks.test_services::test_systemd_timers_ignore_units",
}

ALL_OPTIONS = sorted((cls.id, o.name) for cls in checks.ALL_CHECKS for o in cls.options)


def test_every_option_has_a_behaviour_test() -> None:
    missing = sorted(set(ALL_OPTIONS) - set(OPTION_TESTS))
    stale = sorted(set(OPTION_TESTS) - set(ALL_OPTIONS))
    assert not missing, f"options without a behaviour test in OPTION_TESTS: {missing}"
    assert not stale, f"OPTION_TESTS lists options that no longer exist: {stale}"


def _test_source(ref: str) -> str | None:
    """Source of tests/<module>.py::<function>, read with ast so pytest's import mode
    doesn't matter."""
    module, _, name = ref.partition("::")
    path = ROOT / "tests" / (module.replace(".", "/") + ".py")
    if not path.exists():
        return None
    text = path.read_text()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    return None


@pytest.mark.parametrize("key", sorted(OPTION_TESTS))
def test_named_test_exercises_the_option(key: tuple[str, str]) -> None:
    source = _test_source(OPTION_TESTS[key])
    assert source is not None, f"{OPTION_TESTS[key]} not found"
    # The test must actually set the option, not just be any test that happens to exist.
    assert key[1] in source, f"{OPTION_TESTS[key]} never mentions option {key[1]!r}"


def _options_table() -> list[str]:
    """Rows of the README table whose header is '| Check | Options (defaults) |'."""
    lines = (ROOT / "README.md").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| Check | Options"))
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


@pytest.mark.parametrize("key", ALL_OPTIONS)
def test_option_documented_in_readme(key: tuple[str, str]) -> None:
    check_id, name = key
    rows = _options_table()
    assert any(f"`{check_id}`" in row and f"`{name}`" in row for row in rows), (
        f"README options table has no row for {check_id} listing `{name}`"
    )
