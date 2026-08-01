"""Shared download and cache utilities."""

from __future__ import annotations

import json
import logging
import lzma
import urllib.request
from pathlib import Path

import frida

FRIDA_VERSION: str = frida.__version__
_GH_API = "https://api.github.com/repos/frida/frida/releases/tags/{version}"

logger = logging.getLogger(__name__)


def cache_dir() -> Path:
    p = Path.home() / ".cache" / "enma"
    p.mkdir(parents=True, exist_ok=True)
    return p


def download_github_asset(asset_name: str, out_path: Path, label: str) -> None:
    """Download *asset_name* from the frida GitHub release and decompress if .xz.

    Skips silently when *out_path* already exists (cache hit).
    """
    if out_path.exists():
        return

    url = _GH_API.format(version=FRIDA_VERSION)
    logger.info("[%s] Fetching release info for frida %s ...", label, FRIDA_VERSION)
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
        assets = json.loads(resp.read()).get("assets", [])

    asset_url = next((a["browser_download_url"] for a in assets if a["name"] == asset_name), None)
    if not asset_url:
        raise RuntimeError(f"Asset not found in frida {FRIDA_VERSION}: {asset_name}")

    xz_path = out_path.parent / asset_name
    logger.info("[%s] Downloading %s ...", label, asset_name)
    with (
        urllib.request.urlopen(asset_url, timeout=120) as resp,  # noqa: S310
        xz_path.open("wb") as f,
    ):
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        while chunk := resp.read(65536):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                print(
                    f"\r  {downloaded / total * 100:.1f}%  {downloaded:,}/{total:,} bytes",
                    end="",
                    flush=True,
                )
    print()

    if asset_name.endswith(".xz"):
        logger.info("[%s] Decompressing ...", label)
        with lzma.open(xz_path, "rb") as f_in, out_path.open("wb") as f_out:
            f_out.write(f_in.read())
        xz_path.unlink()
    else:
        xz_path.rename(out_path)
