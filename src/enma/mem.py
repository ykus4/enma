"""mem — interactive memory scanner and patcher.

memscan  : CheatEngine-style value search (scan → filter → results)
mempatch : single-shot write / NOP / byte patch
"""

from __future__ import annotations

import contextlib
import logging
import sys
import time
from typing import Any

import frida

from enma.core.agents import load_agent
from enma.core.session import connect

logger = logging.getLogger(__name__)

_SCAN_TYPES = (
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
    "bytes",
)
_FILTER_TYPES = ("eq", "ne", "gt", "lt", "gte", "lte", "changed", "unchanged")


def _start_agent(args: Any, name: str) -> tuple[frida.core.Session, Any]:
    """Attach to the target, inject *name*, and return (session, rpc exports)."""
    logger.info("Attaching …")
    _device, session = connect(args)
    script = session.create_script(load_agent(name))

    def on_message(msg: dict, _data: bytes | None) -> None:
        if msg["type"] == "error":
            logger.error("JS error: %s", msg["description"])

    script.on("message", on_message)
    script.load()
    return session, script.exports_sync


# ── memscan REPL ──────────────────────────────────────────────────────────────

_SCAN_HELP = """\
Commands:
  scan <value> [type]       First scan  (type: int32 default)
  filter <value> [filter]   Narrow down (filter: eq gt lt changed …)
  results [max]             Show current results (default 50)
  read <addr> <type>        Read value at address
  reset                     Clear all results
  info                      Show scan state
  help                      This message
  quit / exit               Detach and exit
"""


def run_memscan(args: Any) -> None:
    session, rpc = _start_agent(args, "memscan")
    logger.info("Ready.  Type 'help' for commands.")

    try:
        while True:
            try:
                line = input("memscan> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()

            if cmd in ("quit", "exit"):
                break

            elif cmd == "help":
                print(_SCAN_HELP)

            elif cmd == "scan":
                if len(parts) < 2:
                    print("Usage: scan <value> [type]")
                    continue
                t = parts[2] if len(parts) > 2 else "int32"
                if t not in _SCAN_TYPES:
                    print(f"Unknown type. Choose from: {', '.join(_SCAN_TYPES)}")
                    continue
                res = rpc.scan(parts[1], t)
                if "error" in res:
                    print(f"[!] {res['error']}")
                else:
                    print(f"[*] Scan #{res['scanCount']}: {res['count']:,} results")

            elif cmd == "filter":
                if len(parts) < 2:
                    print("Usage: filter <value> [eq|ne|gt|lt|gte|lte|changed|unchanged]")
                    continue
                ft = parts[2] if len(parts) > 2 else "eq"
                if ft not in _FILTER_TYPES:
                    print(f"Unknown filter. Choose from: {', '.join(_FILTER_TYPES)}")
                    continue
                res = rpc.filter(parts[1], ft)
                if "error" in res:
                    print(f"[!] {res['error']}")
                else:
                    print(f"[*] Scan #{res['scanCount']}: {res['count']:,} results remaining")

            elif cmd == "results":
                limit = int(parts[1]) if len(parts) > 1 else 50
                items = rpc.results(limit)
                if not items:
                    print("  (no results)")
                for item in items:
                    print(f"  {item['addr']}  =  {item['value']}")
                total = rpc.info()["resultCount"]
                print(f"  … showing {len(items)} of {total:,}")

            elif cmd == "read":
                if len(parts) < 3:
                    print("Usage: read <addr> <type>")
                    continue
                res = rpc.read(parts[1], parts[2], 1)
                if "error" in res:
                    print(f"[!] {res['error']}")
                else:
                    print(f"  {res['addr']}  =  {res['value']}")

            elif cmd == "reset":
                rpc.reset()
                print("[*] Results cleared.")

            elif cmd == "info":
                info = rpc.info()
                cnt = info["resultCount"]
                print(f"  Type: {info['type']}  Scans: {info['scanCount']}  Results: {cnt:,}")

            else:
                print(f"Unknown command: {cmd}  (type 'help')")

    finally:
        with contextlib.suppress(Exception):
            session.detach()
    logger.info("Detached.")


# ── mempatch one-shot ─────────────────────────────────────────────────────────


def run_mempatch(args: Any) -> None:
    session, rpc = _start_agent(args, "mempatch")
    addr = args.addr

    if args.nop:
        res = rpc.nop(addr, args.nop)
        if "error" in res:
            logger.error("%s", res["error"])
            sys.exit(1)
        logger.info(
            "NOP x%d @ %s  (%d bytes, arch=%s)", args.nop, addr, res["bytesWritten"], res["arch"]
        )

    elif args.bytes:
        res = rpc.write_bytes(addr, " ".join(args.bytes))
        if "error" in res:
            logger.error("%s", res["error"])
            sys.exit(1)
        logger.info("Wrote %s bytes @ %s", res["bytes"], addr)

    elif args.value is not None:
        t = args.type or "int32"
        if args.freeze:
            res = rpc.freeze(addr, t, args.value, args.interval)
            if "error" in res:
                logger.error("%s", res["error"])
                sys.exit(1)
            logger.info(
                "Freezing %s = %s (%s) every %dms  (Ctrl+C to stop)",
                addr,
                args.value,
                t,
                args.interval,
            )
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                rpc.unfreeze(addr)
                print()
                logger.info("Unfrozen.")
        else:
            res = rpc.write(addr, t, args.value)
            if "error" in res:
                logger.error("%s", res["error"])
                sys.exit(1)
            logger.info("Wrote %s (%s) @ %s", res["value"], t, addr)

    else:
        t = args.type or "int32"
        res = rpc.read(addr, t, 1)
        if "error" in res:
            logger.error("%s", res["error"])
            sys.exit(1)
        print(f"  {res['addr']}  =  {res['value']}  ({t})")

    with contextlib.suppress(Exception):
        session.detach()
