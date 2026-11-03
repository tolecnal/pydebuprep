"""pydebuprep-cleanup: show, and with --apply carry out, a cleanup after an upgrade.

Without --apply it only shows (and logs) what it would do. With it: the checks before
acting, the cleanup's own lock, apt's simulation (refused if apt would do more than
planned), a confirmation, then the purges and removals, each logged.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import NoReturn

from pydebuprep import __version__
from pydebuprep.cleanup import runner as runner_module
from pydebuprep.cleanup.act import BACKUP_DIR, execute
from pydebuprep.cleanup.kernels import KEEP_DEFAULT, KEEP_MAX, Package
from pydebuprep.cleanup.log import Log
from pydebuprep.cleanup.plan import PACKAGES_ARGV, Choice, Plan, Refused, build_plan
from pydebuprep.cleanup.runner import Lock, Runner, beyond_plan, preflight, simulate
from pydebuprep.config import ConfigError, load_config
from pydebuprep.system import System

__all__ = ["BACKUP_DIR", "PACKAGES_ARGV", "main"]

USAGE_ERROR, REFUSED, FAILED = 3, 1, 2
CATEGORIES = (
    ("kernels", "Old kernels"),
    ("modules", "Modules and headers of old kernels"),
    ("dirs", "Leftover directories"),
    ("residual", "Configuration left by removed packages"),
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(USAGE_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="pydebuprep-cleanup",
        description="Show, and with --apply carry out, a cleanup after a release upgrade: "
        "old kernels, their modules and headers, leftover directories and the configuration "
        "of removed packages. Without --apply nothing changes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    what = parser.add_argument_group("what to clean up")
    what.add_argument("--kernels", action="store_true", help="old kernel images")
    what.add_argument(
        "--modules", action="store_true", help="modules, headers and tools of old kernels"
    )
    what.add_argument(
        "--leftover-dirs", dest="dirs", action="store_true",
        help="directories of old kernels no package owns, even when not empty (DKMS builds)",
    )  # fmt: skip
    what.add_argument(
        "--residual", action="store_true",
        help="configuration left by removed packages (dpkg state rc), backed up first",
    )  # fmt: skip
    what.add_argument("--all", action="store_true", help="all of the above")
    how = parser.add_argument_group("how")
    how.add_argument(
        "--keep", type=int, default=KEEP_DEFAULT, metavar="N",
        help=f"kernels to keep besides the running one and GRUB's default "
        f"(1 to {KEEP_MAX}, default {KEEP_DEFAULT})",
    )  # fmt: skip
    how.add_argument(
        "--keep-package", action="append", default=[], metavar="PKG",
        help="never purge this package (repeatable)",
    )  # fmt: skip
    how.add_argument("--apply", action="store_true", help="carry out the plan (default: dry run)")
    how.add_argument(
        "--yes", action="store_true", help="don't ask before acting (needed without a terminal)"
    )
    how.add_argument("--json", action="store_true", help="print the plan as JSON")
    conf = how.add_mutually_exclusive_group()
    conf.add_argument("--config", metavar="FILE", help="config file (default /etc/pydebuprep.conf)")
    conf.add_argument("--no-config", action="store_true", help="ignore any config file")
    return parser


def _names(packages: Sequence[Package]) -> list[str]:
    return [p.name for p in packages]


def _plan_json(plan: Plan, *, dry_run: bool) -> str:
    return json.dumps(
        {
            "dry_run": dry_run,
            "kept": list(plan.kept),
            "kernels": _names(plan.kernels),
            "modules": _names(plan.modules),
            "dirs": list(plan.dirs),
            "residual": _names(plan.residual),
            "skipped": list(plan.skipped),
            "size_kib": plan.size_kib,
        },
        indent=2,
    )


def _plan_text(plan: Plan) -> list[str]:
    lines = []
    if plan.kept:
        lines.append(f"Kernels kept: {', '.join(plan.kept)}")
    for attr, label in CATEGORIES:
        items: Sequence[Package | str] = getattr(plan, attr)
        if not items:
            continue
        lines.append(f"{label} ({len(items)}):")
        lines += [f"  {item if isinstance(item, str) else item.name}" for item in items]
    if plan.skipped:
        lines.append(f"Left alone (--keep-package): {', '.join(plan.skipped)}")
    total = len(plan.packages)
    lines.append(
        f"In all: {total} package{'' if total == 1 else 's'} "
        f"({plan.size_kib / 1024:.1f} MiB installed), {len(plan.dirs)} "
        f"director{'y' if len(plan.dirs) == 1 else 'ies'}"
    )
    return lines


def _confirm(plan: Plan, *, yes: bool, interactive: bool, ask: Callable[[str], str]) -> str | None:
    """None to go ahead; otherwise why not."""
    if yes:
        return None
    if not interactive:
        return "not at a terminal: pass --yes to act without being asked"
    question = (
        f"Purge {len(plan.packages)} packages and remove {len(plan.dirs)} directories? [y/N] "
    )
    try:
        answer = ask(question)
    except EOFError:  # Ctrl-D, or input that ended: no
        return "not confirmed"
    return None if answer.strip().lower() in ("y", "yes") else "not confirmed"


def _show(plan: Plan, args: argparse.Namespace, log: Log) -> bool:
    """Print and log the plan; whether there is anything to do."""
    for line in _plan_text(plan):
        log.line(line)
    print(_plan_json(plan, dry_run=not args.apply) if args.json else "\n".join(_plan_text(plan)))
    if plan.packages or plan.dirs:
        return True
    if not args.json:
        print("Nothing to clean up.")
    return False


def _apply(choice: Choice, args: argparse.Namespace, *, system: System, runner: Runner,
           log: Log, now: datetime, interactive: bool, ask: Callable[[str], str],
           remove: Callable[[str], None]) -> int:  # fmt: skip
    """Check, lock, then plan: the plan acted on is the one made under the lock."""
    reasons = preflight(system, runner, dpkg_lock=runner_module.DPKG_LOCK)
    if reasons:
        raise Refused("; ".join(reasons))
    with Lock(runner_module.LOCK_PATH):
        plan = build_plan(system, choice)
        if not _show(plan, args, log):
            return 0
        if plan.packages:
            more = beyond_plan(plan.packages, simulate(runner, plan.packages), plan.arch)
            if more:
                raise Refused(f"apt would also change: {', '.join(sorted(more))}")
        why_not = _confirm(plan, yes=args.yes, interactive=interactive, ask=ask)
        if why_not:
            raise Refused(why_not)
        log.line("acting on the plan")
        code = execute(plan, runner, system, log, now, backup_dir=BACKUP_DIR, remove=remove)
    if code == 0:
        print("Done. Record the result: sudo pydebuprep report")
    return code


def main(
    argv: list[str] | None = None,
    *,
    system: System | None = None,
    runner: Runner | None = None,
    log: Log | None = None,
    now: datetime | None = None,
    interactive: bool | None = None,
    ask: Callable[[str], str] = input,
    remove: Callable[[str], None] = shutil.rmtree,
) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # --help, --version, or a usage error (exit 3)
        return exc.code if isinstance(exc.code, int) else USAGE_ERROR
    every = args.all
    choice_flags = [
        every or args.kernels,
        every or args.modules,
        every or args.dirs,
        every or args.residual,
    ]
    if not any(choice_flags):
        print("pydebuprep-cleanup: choose what to clean up: --kernels, --modules, "
              "--leftover-dirs, --residual or --all", file=sys.stderr)  # fmt: skip
        return USAGE_ERROR
    if not 1 <= args.keep <= KEEP_MAX:
        print(f"pydebuprep-cleanup: --keep must be between 1 and {KEEP_MAX}", file=sys.stderr)
        return USAGE_ERROR
    try:
        config = None if args.no_config else load_config(args.config)
    except ConfigError as exc:
        for problem in exc.errors:
            print(f"pydebuprep-cleanup: {problem}", file=sys.stderr)
        return USAGE_ERROR
    keep_packages = frozenset([*args.keep_package, *(config.cleanup_keep if config else [])])
    system = system or System()
    runner = runner or Runner()
    log = log or Log()
    now = now or datetime.now(timezone.utc)
    interactive = sys.stdin.isatty() if interactive is None else interactive
    try:
        log.line(f"pydebuprep-cleanup {__version__}: {'apply' if args.apply else 'dry run'} "
                 f"{' '.join(argv if argv is not None else sys.argv[1:])}")  # fmt: skip
        choice = Choice(
            kernels=choice_flags[0], modules=choice_flags[1], dirs=choice_flags[2],
            residual=choice_flags[3], keep=args.keep, keep_packages=keep_packages,
        )  # fmt: skip
        if args.apply:
            return _apply(choice, args, system=system, runner=runner, log=log, now=now,
                          interactive=interactive, ask=ask, remove=remove)  # fmt: skip
        if _show(build_plan(system, choice), args, log) and not args.json:
            print("Dry run: nothing changed. Run again with --apply to do this.")
        return 0
    except Refused as exc:
        log.line(f"refused: {exc}")
        print(f"pydebuprep-cleanup: refused: {exc}", file=sys.stderr)
        return REFUSED
    finally:
        log.close()
