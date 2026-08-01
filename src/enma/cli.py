"""enma — Android runtime analysis and research toolkit, powered by Frida.

This module is the CLI surface only: it builds the argument parser and routes to
the feature modules. All runtime logic lives in ``enma.core`` and the per-feature
modules; nothing here should be imported by them.

Feature modules are imported lazily inside each handler so that ``enma --help``,
``enma analyze`` and ``enma report`` never pay for ``frida`` or ``UnityPy``.
"""

from __future__ import annotations

import argparse
import logging

from enma.core import abi
from enma.core.agents import DUMP_AGENTS, UE4_AGENTS

logger = logging.getLogger(__name__)

_PATCH_TYPES = (
    "int8",
    "int16",
    "int32",
    "int64",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "float",
    "double",
)


# ── Subcommand handlers ───────────────────────────────────────────────────────


def run_dump(args: argparse.Namespace) -> None:
    from enma.dump import run_dump as _run

    _run(args)


def list_apps(args: argparse.Namespace) -> None:
    from enma.dump import list_apps as _run

    _run(args)


def run_setup(args: argparse.Namespace) -> None:
    from enma.frida_server import setup_frida_server

    setup_frida_server(serial=args.serial, force=args.force)


def run_repack(args: argparse.Namespace) -> None:
    from enma.repack import repack_apk

    repack_apk(
        apk_path=args.apk, output_apk=args.output, arch=args.arch, keep_workdir=args.keep_workdir
    )


def run_analyze(args: argparse.Namespace) -> None:
    from enma.analyze import analyze_dump

    analyze_dump(dump_dir=args.dump_dir, output=args.output)


def run_report(args: argparse.Namespace) -> None:
    from enma.report import render_report

    render_report(dump_dir=args.dump_dir, report_json=args.json, output=args.output)


def run_unity(args: argparse.Namespace) -> None:
    from enma.unity import extract_bundles

    extract_bundles(dump_dir=args.dump_dir, output_dir=args.output)


def run_ue4(args: argparse.Namespace) -> None:
    from enma.ue4 import run_ue4 as _run

    _run(args)


def run_memscan(args: argparse.Namespace) -> None:
    from enma.mem import run_memscan as _run

    _run(args)


def run_mempatch(args: argparse.Namespace) -> None:
    from enma.mem import run_mempatch as _run

    _run(args)


_DISPATCH = {
    "dump": run_dump,
    "list": list_apps,
    "setup": run_setup,
    "repack": run_repack,
    "analyze": run_analyze,
    "report": run_report,
    "unity": run_unity,
    "ue4": run_ue4,
    "memscan": run_memscan,
    "mempatch": run_mempatch,
}


# ── Shared argument groups ────────────────────────────────────────────────────
#
# `default=argparse.SUPPRESS` matters: a subparser parses into a fresh namespace
# and copies *every* key back, defaults included, so a plain `store_true` on a
# shared parent would clobber the root-level `-v`. Suppressing the default leaves
# the key absent unless the flag was actually given.


def _verbose_parser(short: bool = True) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    flags = ["-v", "--verbose"] if short else ["--verbose"]
    p.add_argument(
        *flags,
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable DEBUG level logging",
    )
    return p


def _target_parser() -> argparse.ArgumentParser:
    """The target/serial/spawn/watch quartet — see core.session.TargetArgs."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("target", help="Package name or PID")
    p.add_argument("-s", "--serial", help="ADB device serial")
    p.add_argument("--spawn", action="store_true", help="Spawn instead of attaching")
    p.add_argument("--watch", action="store_true", help="Wait for app to start, then attach")
    return p


# ── Argument parser ───────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    verbose = _verbose_parser()
    # mempatch already owns -v for --value, so it gets the long form only.
    verbose_long = _verbose_parser(short=False)
    target = _target_parser()

    parser = argparse.ArgumentParser(
        prog="enma",
        description="enma — Android runtime analysis and research toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available agent types: {', '.join(DUMP_AGENTS)}",
        parents=[verbose],
    )
    sub = parser.add_subparsers(dest="command")

    # dump
    p = sub.add_parser("dump", help="Dump memory artifacts from an app", parents=[verbose, target])
    p.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=list(DUMP_AGENTS),
        metavar="TYPE",
        help=f"Agent types to run (default: all). Choices: {', '.join(DUMP_AGENTS)}",
    )
    p.add_argument("-o", "--output", default="./dump", help="Output dir (default: ./dump)")
    p.add_argument("--retry", action="store_true", help="Re-attach automatically when process dies")
    p.add_argument(
        "--timeout",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Auto-detach after N seconds (0 = run until Ctrl+C)",
    )

    # list
    p = sub.add_parser("list", help="List installed apps on device", parents=[verbose])
    p.add_argument("-s", "--serial", help="ADB device serial")

    # setup
    p = sub.add_parser("setup", help="Push and start frida-server on device", parents=[verbose])
    p.add_argument("-s", "--serial", help="ADB device serial")
    p.add_argument("-f", "--force", action="store_true", help="Force re-push")

    # repack
    p = sub.add_parser(
        "repack", help="Inject frida-gadget into an APK (no root needed)", parents=[verbose]
    )
    p.add_argument("apk", help="Path to the APK to repack")
    p.add_argument("-o", "--output", default=None, help="Output APK path")
    p.add_argument(
        "--arch",
        default=abi.DEFAULT_ARCH,
        choices=list(abi.ARCHES),
        help=f"Target CPU architecture (default: {abi.DEFAULT_ARCH})",
    )
    p.add_argument("--keep-workdir", action="store_true", help="Keep intermediate work dir")

    # analyze
    p = sub.add_parser(
        "analyze", help="Run post-dump analysis on a dump directory", parents=[verbose]
    )
    p.add_argument("dump_dir", help="Path to dump directory produced by 'dump'")
    p.add_argument("-o", "--output", default=None, help="Output report.json path")

    # report
    p = sub.add_parser("report", help="Generate HTML report from report.json", parents=[verbose])
    p.add_argument("dump_dir", help="Path to dump directory containing report.json")
    p.add_argument("--json", default=None, help="Custom report.json path")
    p.add_argument("-o", "--output", default=None, help="Output HTML path")

    # unity
    p = sub.add_parser(
        "unity", help="Extract assets from Unity AssetBundle files", parents=[verbose]
    )
    p.add_argument("dump_dir", help="Path to dump directory containing .unity3d files")
    p.add_argument("-o", "--output", default=None, help="Output directory for extracted assets")

    # ue4
    p = sub.add_parser(
        "ue4",
        help="Unreal Engine 4 analysis (SDK dump, PAK, Blueprint trace)",
        parents=[verbose, target],
    )
    p.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=list(UE4_AGENTS),
        metavar="TYPE",
        help=f"UE4 agent(s) to run (default: all). Choices: {', '.join(UE4_AGENTS)}",
    )
    p.add_argument("-o", "--output", default="./dump", help="Output directory (default: ./dump)")
    p.add_argument(
        "--gnames", default=None, metavar="ADDR", help="GNames / FNamePool address (hex)"
    )
    p.add_argument("--gobjects", default=None, metavar="ADDR", help="GUObjectArray address (hex)")
    p.add_argument(
        "--process-event",
        default=None,
        metavar="ADDR",
        help="UObject::ProcessEvent address (hex)",
    )
    p.add_argument(
        "--extract-pak",
        action="store_true",
        help="Run u4pak extraction on discovered PAK files after dump",
    )

    # memscan
    sub.add_parser(
        "memscan",
        help="Interactive CheatEngine-style memory value scanner",
        parents=[verbose, target],
    )

    # mempatch
    p = sub.add_parser(
        "mempatch", help="Write / NOP / freeze a memory address", parents=[verbose_long, target]
    )
    p.add_argument("addr", help="Target address (hex, e.g. 0x7ff1234)")
    p.add_argument(
        "-t",
        "--type",
        default="int32",
        choices=list(_PATCH_TYPES),
        help="Value type (default: int32)",
    )
    p.add_argument("-v", "--value", default=None, help="Value to write")
    p.add_argument(
        "--nop", type=int, default=0, metavar="COUNT", help="Write COUNT NOP instructions"
    )
    p.add_argument(
        "--bytes", nargs="+", metavar="HEX", help="Write raw bytes (hex, e.g. DE AD BE EF)"
    )
    p.add_argument("--freeze", action="store_true", help="Continuously write value (lock it)")
    p.add_argument(
        "--interval", type=int, default=100, metavar="MS", help="Freeze interval ms (default 100)"
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(message)s",
    )
    fn = _DISPATCH.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
