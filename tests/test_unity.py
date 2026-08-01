"""UnityPy is stubbed throughout, so the suite never pays its ~0.5s import."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import ModuleType

import pytest

from enma import unity
from enma.unity import extract_bundles


@pytest.fixture
def stub_unitypy(monkeypatch: pytest.MonkeyPatch):
    mod = types.ModuleType("UnityPy")
    mod.load = lambda _path: types.SimpleNamespace(objects=[])
    monkeypatch.setitem(sys.modules, "UnityPy", mod)
    return mod


def test_unavailable_unitypy_returns_error_dict(
    dump_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(unity, "_unitypy_available", lambda: False)
    assert extract_bundles(str(dump_dir)) == {"error": "UnityPy not installed", "extracted": 0}


def test_unavailable_unitypy_creates_no_output_dir(
    dump_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(unity, "_unitypy_available", lambda: False)
    extract_bundles(str(dump_dir))
    assert not (dump_dir / "unity_extracted").exists()


def test_no_bundles_found_returns_zero_summary(dump_dir: Path, stub_unitypy: ModuleType) -> None:
    assert extract_bundles(str(dump_dir)) == {"bundles": 0, "extracted": 0}


def test_no_bundles_creates_no_output_dir(dump_dir: Path, stub_unitypy: ModuleType) -> None:
    extract_bundles(str(dump_dir))
    assert not (dump_dir / "unity_extracted").exists()


def test_bundle_load_failure_is_recorded_not_raised(
    dump_dir: Path, stub_unitypy: ModuleType
) -> None:
    (dump_dir / "a.unity3d").write_bytes(b"garbage")
    stub_unitypy.load = lambda _p: (_ for _ in ()).throw(ValueError("bad header"))
    summary = extract_bundles(str(dump_dir))
    assert summary["bundles"] == 1
    assert summary["extracted"] == 0
    assert summary["errors"][0]["file"] == "a.unity3d"


def test_textasset_is_exported(dump_dir: Path, stub_unitypy: ModuleType) -> None:
    (dump_dir / "a.unity3d").write_bytes(b"stub")
    obj = types.SimpleNamespace(
        type=types.SimpleNamespace(name="TextAsset"),
        read=lambda: types.SimpleNamespace(name="config", text="hello"),
    )
    stub_unitypy.load = lambda _p: types.SimpleNamespace(objects=[obj])
    summary = extract_bundles(str(dump_dir))
    assert summary == {
        "bundles": 1,
        "extracted": 1,
        "by_type": {"TextAsset": 1},
        "errors": [],
    }
    assert (dump_dir / "unity_extracted" / "config.txt").read_text() == "hello"


def test_export_failure_is_recorded_per_object(dump_dir: Path, stub_unitypy: ModuleType) -> None:
    (dump_dir / "a.unity3d").write_bytes(b"stub")
    obj = types.SimpleNamespace(
        type=types.SimpleNamespace(name="Texture2D"),
        read=lambda: (_ for _ in ()).throw(RuntimeError("no decoder")),
    )
    stub_unitypy.load = lambda _p: types.SimpleNamespace(objects=[obj])
    summary = extract_bundles(str(dump_dir))
    assert summary["extracted"] == 0
    assert summary["errors"][0]["type"] == "Texture2D"
