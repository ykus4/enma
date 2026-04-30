"""frida-server auto-push and start helper."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time

from enma._util import FRIDA_VERSION, cache_dir, download_github_asset

logger = logging.getLogger(__name__)

FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/frida-server"

_ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def _adb(*args: str, serial: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _device_arch(serial: str | None) -> str:
    result = _adb("shell", "getprop", "ro.product.cpu.abi", serial=serial)
    return _ABI_MAP.get(result.stdout.strip(), "arm64")


def _server_running(serial: str | None) -> bool:
    try:
        result = _adb("shell", "pgrep", "-x", "frida-server", serial=serial, check=False)
        return result.returncode == 0
    except Exception:
        return False


def _remote_version(serial: str | None) -> str | None:
    try:
        r = _adb("shell", FRIDA_SERVER_DEVICE_PATH, "--version", serial=serial, check=False)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def setup_frida_server(serial: str | None = None, force: bool = False) -> None:
    """Push and start frida-server on the connected device."""
    logger.info("frida version: %s", FRIDA_VERSION)

    try:
        _adb("get-state", serial=serial)
    except subprocess.CalledProcessError:
        logger.error("ADB: device not found or not authorized.")
        sys.exit(1)

    if not force and _server_running(serial):
        remote_ver = _remote_version(serial)
        if remote_ver == FRIDA_VERSION:
            logger.info("frida-server %s already running — nothing to do.", remote_ver)
            return
        logger.info("Running: %s, local: %s — updating.", remote_ver, FRIDA_VERSION)
        _adb("shell", "su", "-c", "pkill -9 frida-server", serial=serial, check=False)

    arch = _device_arch(serial)
    logger.info("Device arch: %s", arch)

    asset_name = f"frida-server-{FRIDA_VERSION}-android-{arch}.xz"
    bin_path = cache_dir() / f"frida-server-{FRIDA_VERSION}-android-{arch}"
    download_github_asset(asset_name, bin_path, "setup")
    if not os.access(bin_path, os.X_OK):
        os.chmod(bin_path, 0o755)

    logger.info("Pushing to %s ...", FRIDA_SERVER_DEVICE_PATH)
    _adb("push", str(bin_path), FRIDA_SERVER_DEVICE_PATH, serial=serial)
    _adb("shell", "su", "-c", f"chmod 755 {FRIDA_SERVER_DEVICE_PATH}", serial=serial)

    logger.info("Starting frida-server ...")
    _adb("shell", "su", "-c", f"nohup {FRIDA_SERVER_DEVICE_PATH} &", serial=serial)

    time.sleep(1.5)
    if _server_running(serial):
        logger.info("frida-server is running.")
    else:
        logger.warning("frida-server may not have started. Check device logs.")
