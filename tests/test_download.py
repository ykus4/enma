from __future__ import annotations

from pathlib import Path

from enma.core.download import FRIDA_VERSION, cache_dir, download_github_asset


def test_cache_hit_returns_without_touching_the_network(tmp_path: Path) -> None:
    """The autouse no_network fixture makes urlopen raise, so reaching it fails."""
    out = tmp_path / "frida-server-x"
    out.write_bytes(b"already here")
    download_github_asset("frida-server-1.0.0-android-arm64.xz", out, "setup")
    assert out.read_bytes() == b"already here"


def test_cache_dir_is_created_under_home(tmp_path: Path) -> None:
    d = cache_dir()
    assert d.is_dir()
    assert d == Path.home() / ".cache" / "enma"
    assert tmp_path in d.parents


def test_cache_dir_is_idempotent() -> None:
    assert cache_dir() == cache_dir()


def test_frida_version_matches_installed_package() -> None:
    import frida

    assert frida.__version__ == FRIDA_VERSION
