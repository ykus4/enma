#!/usr/bin/env python3
"""androDumper — Android security research memory dump tool.

Supports: DEX, IL2CPP, Unity Assets, Mono, SSL bypass, Crypto, JNI, Heap,
          Coverage, Tracer, Binder, Anti-detect, Anti-tamper, SafetyNet,
          HTTP, WebSocket, Protobuf, SQLite, File I/O, dlopen
Requires: frida-tools, adb, rooted device or emulator
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.resources
import json
import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import frida

logger = logging.getLogger(__name__)

AGENT_NAMES = (
    # core dump
    "dex",
    "il2cpp",
    "assets",
    "mono",
    "ssl",
    "crypto",
    "jni",
    "heap",
    # dynamic analysis
    "coverage",
    "tracer",
    "binder",
    # bypass
    "anti_detect",
    "anti_tamper",
    "safetynet",
    # protocol / storage
    "http",
    "websocket",
    "protobuf",
    "sqlite",
    "fileio",
    "dlopen",
    # Unreal Engine
    "ue4_sdk",
    "ue4_pak",
    "ue4_blueprint",
)

# Maps agent name → agents/ subdirectory
_AGENT_DIR: dict[str, str] = {
    "dex": "dump",
    "il2cpp": "dump",
    "assets": "dump",
    "mono": "dump",
    "heap": "dump",
    "coverage": "analysis",
    "tracer": "analysis",
    "jni": "analysis",
    "ssl": "bypass",
    "crypto": "bypass",
    "anti_detect": "bypass",
    "anti_tamper": "bypass",
    "safetynet": "bypass",
    "http": "network",
    "websocket": "network",
    "protobuf": "network",
    "binder": "network",
    "sqlite": "storage",
    "fileio": "storage",
    "dlopen": "storage",
    "ue4_sdk": "ue4",
    "ue4_pak": "ue4",
    "ue4_blueprint": "ue4",
}


def load_agent(name: str) -> str:
    subdir = _AGENT_DIR[name]
    ref = importlib.resources.files("enma.agents").joinpath(subdir).joinpath(f"{name}_agent.js")
    return ref.read_text(encoding="utf-8")


# ── Device selection ──────────────────────────────────────────────────────────


def get_device(serial: str | None) -> frida.core.Device:
    dm = frida.get_device_manager()
    if serial:
        return dm.get_device(serial)
    devices = [d for d in dm.enumerate_devices() if d.type == "usb"]
    if not devices:
        devices = [d for d in dm.enumerate_devices() if d.type == "remote"]
    if not devices:
        logger.error("No device found. Connect a device or start an emulator.")
        sys.exit(1)
    if len(devices) == 1:
        return devices[0]
    logger.info("Multiple devices found:")
    for i, d in enumerate(devices):
        print(f"    [{i}] {d.id}  {d.name}")
    while True:
        try:
            idx = int(input("Select device index: "))
            return devices[idx]
        except (ValueError, IndexError):
            logger.warning("Enter a number between 0 and %d.", len(devices) - 1)


# ── Attach / spawn ────────────────────────────────────────────────────────────


def attach_or_spawn(device: frida.core.Device, target: str, spawn: bool) -> frida.core.Session:
    if spawn:
        logger.info("Spawning %s ...", target)
        pid = device.spawn([target])
        session = device.attach(pid)
        device.resume(pid)
        return session
    logger.info("Attaching to %s ...", target)
    return device.attach(target)


# ── Message handler factory ───────────────────────────────────────────────────


def make_on_message(
    name: str, out_dir: str, lock: threading.Lock
) -> Callable[[dict, bytes | None], None]:
    def on_message(message: dict, data: bytes | None) -> None:
        if message["type"] == "error":
            with lock:
                logger.error("[%s] %s", name, message["description"])
                if stack := message.get("stack"):
                    logger.debug("%s", stack)
            return

        payload = message.get("payload", {})
        kind = payload.get("event")

        if kind == "log":
            with lock:
                logger.info("[%s] %s", name, payload["message"])
        elif kind == "file":
            fname = payload["name"]
            fpath = os.path.join(out_dir, fname)
            with lock:
                if data:
                    Path(fpath).write_bytes(data)
                    size_str = f"{len(data):,}"
                    logger.info("[%s] Saved %s  (%s bytes)  -> %s", name, fname, size_str, fpath)
                else:
                    logger.warning("[%s] empty data for %s", name, fname)
        elif kind == "json":
            fname = payload["name"]
            fpath = os.path.join(out_dir, fname)
            with lock:
                with open(fpath, "w") as f:
                    json.dump(payload["data"], f, indent=2)
                logger.info("[%s] Saved %s -> %s", name, fname, fpath)

    return on_message


# ── Watch mode ────────────────────────────────────────────────────────────────


def wait_for_process(
    device: frida.core.Device, package: str, poll_interval: float = 1.0
) -> frida.core.Session:
    logger.info("Watch mode: waiting for %s to start ...", package)
    while True:
        for app in device.enumerate_applications():
            if app.identifier == package and app.pid:
                logger.info("%s started (PID %s)", package, app.pid)
                return device.attach(app.pid)
        time.sleep(poll_interval)


# ── Load scripts ──────────────────────────────────────────────────────────────


def load_scripts(
    session: frida.core.Session,
    agents: list[str],
    out_dir: str,
    lock: threading.Lock,
) -> dict[str, frida.core.Script]:
    scripts: dict[str, frida.core.Script] = {}
    for agent_name in agents:
        try:
            source = load_agent(agent_name)
        except FileNotFoundError:
            logger.error("Agent not found: %s", agent_name)
            continue
        script = session.create_script(source)
        script.on("message", make_on_message(agent_name, out_dir, lock))
        scripts[agent_name] = script

    for name, script in scripts.items():
        logger.info("Loading agent: %s", name)
        script.load()

    return scripts


# ── Subcommand handlers ───────────────────────────────────────────────────────


def run_dump(args: argparse.Namespace) -> None:
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    device = get_device(args.serial)
    agents = list(args.type) if args.type else list(AGENT_NAMES)
    lock = threading.Lock()

    def one_session() -> None:
        session = (
            wait_for_process(device, args.target)
            if args.watch
            else attach_or_spawn(device, args.target, args.spawn)
        )
        load_scripts(session, agents, out_dir, lock)

        timeout: int = args.timeout or 0
        if timeout > 0:
            logger.info("Will auto-detach after %ds", timeout)
            t = threading.Timer(timeout, lambda: os.kill(os.getpid(), signal.SIGINT))
            t.daemon = True
            t.start()

        done = threading.Event()
        session.on(
            "detached",
            lambda reason, crash: (logger.info("Detached: %s", reason), done.set()),
        )
        try:
            done.wait()
        except KeyboardInterrupt:
            raise
        finally:
            with contextlib.suppress(Exception):
                session.detach()

    attempt = 0
    while True:
        attempt += 1
        try:
            one_session()
        except KeyboardInterrupt:
            print()
            logger.info("Stopped.")
            break
        except Exception as e:
            logger.error("Session error: %s", e)

        if not args.retry:
            break
        logger.info("Re-attach: waiting for %s to restart (attempt %d) ...", args.target, attempt)
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print()
            logger.info("Stopped.")
            break


def list_apps(args: argparse.Namespace) -> None:
    device = get_device(args.serial)
    for app in sorted(device.enumerate_applications(), key=lambda a: a.identifier):
        running = f" [PID {app.pid}]" if app.pid else ""
        print(f"  {app.identifier:<50} {app.name}{running}")


def run_setup(args: argparse.Namespace) -> None:
    from enma.device import setup_frida_server

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


# ── Argument parser ───────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="androDumper — Android security research memory dump tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available agent types: {', '.join(AGENT_NAMES)}",
    )
    sub = parser.add_subparsers(dest="command")

    # dump
    p = sub.add_parser("dump", help="Dump memory artifacts from an app")
    p.add_argument("target", help="Package name or PID")
    p.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=list(AGENT_NAMES),
        metavar="TYPE",
        help=f"Agent types to run (default: all). Choices: {', '.join(AGENT_NAMES)}",
    )
    p.add_argument("-o", "--output", default="./dump", help="Output dir (default: ./dump)")
    p.add_argument("-s", "--serial", help="ADB device serial")
    p.add_argument("--spawn", action="store_true", help="Spawn instead of attaching")
    p.add_argument("--watch", action="store_true", help="Wait for app to start, then attach")
    p.add_argument("--retry", action="store_true", help="Re-attach automatically when process dies")
    p.add_argument(
        "--timeout",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Auto-detach after N seconds (0 = run until Ctrl+C)",
    )

    # list
    p = sub.add_parser("list", help="List installed apps on device")
    p.add_argument("-s", "--serial", help="ADB device serial")

    # setup
    p = sub.add_parser("setup", help="Push and start frida-server on device")
    p.add_argument("-s", "--serial", help="ADB device serial")
    p.add_argument("-f", "--force", action="store_true", help="Force re-push")

    # repack
    p = sub.add_parser("repack", help="Inject frida-gadget into an APK (no root needed)")
    p.add_argument("apk", help="Path to the APK to repack")
    p.add_argument("-o", "--output", default=None, help="Output APK path")
    p.add_argument(
        "--arch",
        default="arm64",
        choices=["arm64", "arm", "x86_64", "x86"],
        help="Target CPU architecture (default: arm64)",
    )
    p.add_argument("--keep-workdir", action="store_true", help="Keep intermediate work dir")

    # analyze
    p = sub.add_parser("analyze", help="Run post-dump analysis on a dump directory")
    p.add_argument("dump_dir", help="Path to dump directory produced by 'dump'")
    p.add_argument("-o", "--output", default=None, help="Output report.json path")

    # report
    p = sub.add_parser("report", help="Generate HTML report from report.json")
    p.add_argument("dump_dir", help="Path to dump directory containing report.json")
    p.add_argument("--json", default=None, help="Custom report.json path")
    p.add_argument("-o", "--output", default=None, help="Output HTML path")

    # unity
    p = sub.add_parser("unity", help="Extract assets from Unity AssetBundle files")
    p.add_argument("dump_dir", help="Path to dump directory containing .unity3d files")
    p.add_argument("-o", "--output", default=None, help="Output directory for extracted assets")

    # ue4
    _UE4_AGENTS = ["ue4_sdk", "ue4_pak", "ue4_blueprint"]
    p = sub.add_parser("ue4", help="Unreal Engine 4 analysis (SDK dump, PAK, Blueprint trace)")
    p.add_argument("target", help="Package name or PID")
    p.add_argument(
        "-t",
        "--type",
        nargs="+",
        choices=_UE4_AGENTS,
        metavar="TYPE",
        help=f"UE4 agent(s) to run (default: all). Choices: {', '.join(_UE4_AGENTS)}",
    )
    p.add_argument("-o", "--output", default="./dump", help="Output directory (default: ./dump)")
    p.add_argument("-s", "--serial", help="ADB device serial")
    p.add_argument("--spawn", action="store_true", help="Spawn instead of attaching")
    p.add_argument("--watch", action="store_true", help="Wait for app to start, then attach")
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

    # memscan — shared args helper
    def _add_target_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("target", help="Package name or PID")
        p.add_argument("-s", "--serial", help="ADB device serial")
        p.add_argument("--spawn", action="store_true", help="Spawn instead of attaching")
        p.add_argument("--watch", action="store_true", help="Wait for app to start, then attach")

    p = sub.add_parser("memscan", help="Interactive CheatEngine-style memory value scanner")
    _add_target_args(p)

    # mempatch
    p = sub.add_parser("mempatch", help="Write / NOP / freeze a memory address")
    _add_target_args(p)
    _PATCH_TYPES = [
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
    ]
    p.add_argument("addr", help="Target address (hex, e.g. 0x7ff1234)")
    p.add_argument(
        "-t", "--type", default="int32", choices=_PATCH_TYPES, help="Value type (default: int32)"
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

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG level logging")

    return parser


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
