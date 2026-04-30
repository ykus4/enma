"""ue4 — Unreal Engine 4 support: agent orchestration and PAK extraction."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def run_ue4(args: argparse.Namespace) -> None:
    """Orchestrate UE4 agents and optionally extract PAK contents."""
    import threading

    from enma.cli import attach_or_spawn, get_device, load_agent, make_on_message, wait_for_process

    device = get_device(args.serial)
    session = (
        wait_for_process(device, args.target)
        if args.watch
        else attach_or_spawn(device, args.target, args.spawn)
    )

    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    lock = threading.Lock()
    agents: list[str] = list(args.type) if args.type else ["ue4_sdk", "ue4_pak", "ue4_blueprint"]

    scripts = {}
    for agent_name in agents:
        source = load_agent(agent_name)
        script = session.create_script(source)
        script.on("message", make_on_message(agent_name, str(out_dir), lock))
        scripts[agent_name] = script

    for name, script in scripts.items():
        logger.info("Loading agent: %s", name)
        script.load()

    if "ue4_sdk" in scripts:
        opts: dict = {}
        if args.gnames:
            opts["gnamesPtr"] = args.gnames
        if args.gobjects:
            opts["gobjectsPtr"] = args.gobjects
        if opts:
            logger.info("Configuring ue4_sdk: %s", opts)
            scripts["ue4_sdk"].exports_sync.configure(opts)

    if "ue4_blueprint" in scripts:
        bp_opts: dict = {}
        if args.process_event:
            bp_opts["processEventAddr"] = args.process_event
        if args.gnames:
            bp_opts["gnamesPtr"] = args.gnames
        if bp_opts:
            scripts["ue4_blueprint"].exports_sync.configure(bp_opts)

    done = threading.Event()
    session.on(
        "detached",
        lambda reason, _crash: (logger.info("Detached: %s", reason), done.set()),
    )
    try:
        done.wait()
    except KeyboardInterrupt:
        print()
        logger.info("Flushing traces ...")
        if "ue4_blueprint" in scripts:
            with contextlib.suppress(Exception):
                scripts["ue4_blueprint"].exports_sync.flush()
        if "ue4_pak" in scripts:
            with contextlib.suppress(Exception):
                scripts["ue4_pak"].exports_sync.scan()
    finally:
        with contextlib.suppress(Exception):
            session.detach()

    if args.extract_pak:
        pak_list_file = out_dir / "ue4_pak_list.json"
        if pak_list_file.exists():
            extract_paks(pak_list_file, out_dir)
        else:
            logger.warning("No ue4_pak_list.json found — skipping PAK extraction")


def extract_paks(pak_list_file: Path, out_dir: Path) -> None:
    """Extract UE4 PAK file contents using u4pak (if installed)."""
    import shutil
    import subprocess

    u4pak = shutil.which("u4pak") or shutil.which("u4pak.py")
    if not u4pak:
        logger.error("u4pak not found. Install it: pip install u4pak")
        logger.info("PAK list saved to: %s", pak_list_file)
        return

    pak_list = json.loads(pak_list_file.read_text())
    pak_files = [p.get("path", "") for p in pak_list if p.get("path", "").endswith(".pak")]
    pak_files += [str(f) for f in out_dir.glob("ue4_pak_*.pak")]

    if not pak_files:
        logger.warning("No .pak file paths to extract")
        return

    for pak_path in pak_files:
        p = Path(pak_path)
        if not p.exists():
            logger.warning("Skipping %s (not accessible on this machine)", pak_path)
            continue
        out = out_dir / f"pak_extracted_{p.stem}"
        out.mkdir(exist_ok=True)
        logger.info("Extracting %s -> %s", p.name, out)
        result = subprocess.run(
            [u4pak, "extract", "--", str(p), str(out)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            extracted = list(out.rglob("*"))
            logger.info("Extracted %d file(s) from %s", len(extracted), p.name)
        else:
            logger.error("u4pak failed on %s: %s", p.name, result.stderr[:500])


def analyze_ue4_dump(dump_dir: Path, report: dict) -> None:
    """Analyze UE4 dump artifacts and add findings to report dict."""
    sdk_file = dump_dir / "ue4_sdk.json"
    pak_file = dump_dir / "ue4_pak_list.json"
    bp_file = dump_dir / "ue4_blueprint_trace.json"

    section: dict = {}

    if sdk_file.exists():
        sdk = json.loads(sdk_file.read_text())
        stats = sdk.get("stats", {})
        section["sdk"] = {
            "total_objects": stats.get("totalObjects", 0),
            "total_names": stats.get("totalNames", 0),
            "classes": stats.get("classes", 0),
            "functions": stats.get("functions", 0),
            "enums": stats.get("enums", 0),
            "structs": stats.get("structs", 0),
            "class_names": sdk.get("classes", [])[:200],
            "function_names": sdk.get("functions", [])[:200],
        }
        logger.info(
            "UE4 SDK: %d classes, %d functions",
            stats.get("classes", 0),
            stats.get("functions", 0),
        )

    if pak_file.exists():
        pak_list = json.loads(pak_file.read_text())
        section["pak_files"] = pak_list
        logger.info("UE4 PAK: %d PAK location(s)", len(pak_list))

    if bp_file.exists():
        bp = json.loads(bp_file.read_text())
        total = bp.get("total", 0)
        entries = bp.get("entries", [])
        func_counts: dict = {}
        for e in entries:
            k = e.get("func", "?")
            func_counts[k] = func_counts.get(k, 0) + 1
        top = dict(sorted(func_counts.items(), key=lambda x: -x[1])[:50])
        section["blueprint_trace"] = {
            "total_calls": total,
            "capped": bp.get("capped", False),
            "top_functions": top,
        }
        logger.info("UE4 Blueprint: %d call(s) traced", total)

    if section:
        report["ue4"] = section


def main_analyze(dump_dir: str, output: str | None = None) -> None:
    """Standalone entry point for UE4-only post-dump analysis."""
    path = Path(dump_dir).resolve()
    if not path.is_dir():
        logger.error("Directory not found: %s", path)
        sys.exit(1)

    report: dict = {}
    analyze_ue4_dump(path, report)

    out = Path(output) if output else path / "ue4_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    logger.info("Report saved: %s", out)
