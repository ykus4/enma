"""Frida device and session plumbing shared by dump, ue4 and mem."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

import frida

from enma.core.agents import UnknownAgentError, load_agent

logger = logging.getLogger(__name__)


class TargetArgs(Protocol):
    """Structural type for the argparse namespace of any target-taking command.

    The dump / ue4 / memscan / mempatch subparsers all define exactly these four
    options via a shared ``parents=`` parser. Declared as a Protocol so that
    ``core`` never has to import argparse or the CLI.
    """

    target: str
    serial: str | None
    spawn: bool
    watch: bool


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


# ── Attach / spawn / watch ────────────────────────────────────────────────────


def attach_or_spawn(device: frida.core.Device, target: str, spawn: bool) -> frida.core.Session:
    if spawn:
        logger.info("Spawning %s ...", target)
        pid = device.spawn([target])
        session = device.attach(pid)
        device.resume(pid)
        return session
    logger.info("Attaching to %s ...", target)
    return device.attach(target)


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


def open_session(
    device: frida.core.Device, target: str, *, spawn: bool = False, watch: bool = False
) -> frida.core.Session:
    if watch:
        return wait_for_process(device, target)
    return attach_or_spawn(device, target, spawn)


def connect(args: TargetArgs) -> tuple[frida.core.Device, frida.core.Session]:
    """``get_device`` + ``open_session`` — what every target-taking command does."""
    device = get_device(args.serial)
    return device, open_session(device, args.target, spawn=args.spawn, watch=args.watch)


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
            fpath = Path(out_dir) / fname
            with lock:
                if data:
                    fpath.write_bytes(data)
                    size_str = f"{len(data):,}"
                    logger.info("[%s] Saved %s  (%s bytes)  -> %s", name, fname, size_str, fpath)
                else:
                    logger.warning("[%s] empty data for %s", name, fname)
        elif kind == "json":
            fname = payload["name"]
            fpath = Path(out_dir) / fname
            with lock:
                fpath.write_text(json.dumps(payload["data"], indent=2), encoding="utf-8")
                logger.info("[%s] Saved %s -> %s", name, fname, fpath)

    return on_message


# ── Script loading ────────────────────────────────────────────────────────────


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
        except (UnknownAgentError, FileNotFoundError):
            logger.error("Agent not found: %s", agent_name)
            continue
        script = session.create_script(source)
        script.on("message", make_on_message(agent_name, out_dir, lock))
        scripts[agent_name] = script

    for name, script in scripts.items():
        logger.info("Loading agent: %s", name)
        script.load()

    return scripts


# ── Session lifetime ──────────────────────────────────────────────────────────


def run_until_detached(
    session: frida.core.Session,
    *,
    timeout: int = 0,
    on_interrupt: Callable[[], None] | None = None,
) -> bool:
    """Block until the session detaches or the user interrupts.

    A *timeout* above zero arms a daemon timer that raises KeyboardInterrupt in
    the main thread after N seconds. *on_interrupt* runs once, before detaching,
    when interrupted — ue4 uses it to flush blueprint traces and rescan PAKs.
    The session is always detached on the way out.

    Returns True when the wait ended via Ctrl+C or the timeout, False on a normal
    detach. The interrupt is deliberately **not** re-raised: ``run_dump`` wants to
    break its retry loop, while ``run_ue4`` needs to keep going so ``--extract-pak``
    still runs. Returning a flag serves both.
    """
    if timeout > 0:
        logger.info("Will auto-detach after %ds", timeout)
        timer = threading.Timer(timeout, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.daemon = True
        timer.start()

    done = threading.Event()
    session.on(
        "detached",
        lambda reason, _crash: (logger.info("Detached: %s", reason), done.set()),
    )
    interrupted = False
    try:
        done.wait()
    except KeyboardInterrupt:
        interrupted = True
        print()
        if on_interrupt is not None:
            on_interrupt()
    finally:
        with contextlib.suppress(Exception):
            session.detach()
    return interrupted
