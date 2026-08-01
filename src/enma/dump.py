"""dump — run JS agents against a target process and collect their output."""

from __future__ import annotations

import argparse
import logging
import threading
import time
from pathlib import Path

from enma.core.agents import DUMP_AGENTS
from enma.core.session import get_device, load_scripts, open_session, run_until_detached

logger = logging.getLogger(__name__)


def run_dump(args: argparse.Namespace) -> None:
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Selected once, outside the retry loop: re-running get_device() per attempt
    # would re-prompt for a device on every re-attach and block --retry on stdin.
    device = get_device(args.serial)
    agents = list(args.type) if args.type else list(DUMP_AGENTS)
    lock = threading.Lock()

    def one_session() -> bool:
        session = open_session(device, args.target, spawn=args.spawn, watch=args.watch)
        load_scripts(session, agents, str(out_dir), lock)
        return run_until_detached(session, timeout=args.timeout or 0)

    attempt = 0
    while True:
        attempt += 1
        try:
            if one_session():
                logger.info("Stopped.")
                break
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
