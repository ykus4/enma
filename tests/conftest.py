"""Shared fixtures.

The autouse fixtures here enforce the suite's core constraint rather than merely
assuming it: no test may reach the network, shell out to an external tool, or
touch the real ``~/.cache/enma``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest


@pytest.fixture
def dump_dir(tmp_path: Path) -> Path:
    """An empty dump directory."""
    d = tmp_path / "dump"
    d.mkdir()
    return d


@pytest.fixture
def write_artifact(dump_dir: Path):
    """``write_artifact("jni_map.json", [...]) -> Path``"""

    def _write(name: str, payload: object) -> Path:
        p = dump_dir / name
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    return _write


@pytest.fixture(autouse=True)
def no_external_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """analyze / repack / ue4 must never shell out during tests."""
    monkeypatch.setattr("enma.analyze._find", lambda _tool: None)
    monkeypatch.setattr(shutil, "which", lambda _tool, *a, **kw: None)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_kw: object) -> None:
        raise AssertionError("network access attempted in a test")

    monkeypatch.setattr("urllib.request.urlopen", _boom)


@pytest.fixture(autouse=True)
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """cache_dir() otherwise mkdirs into the real ~/.cache/enma."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))


@pytest.fixture
def sample_report() -> dict:
    """One entry per _RENDERERS key, plus one unknown key for the generic path."""
    return {
        "dump_dir": "/tmp/dump",
        "tool_versions": {"jadx": None, "apktool": None},
        "dex": {
            "files": ["classes.dex"],
            "jadx": {"java_files": 12},
            "obfuscation": {"obfRatioPct": 73, "verdict": "heavily obfuscated"},
        },
        "il2cpp": {
            "methods": 2,
            "fields": 1,
            "interesting_methods": [{"Name": "GetToken", "Signature": "()", "Address": "0x1"}],
        },
        "jni": {"total_mappings": 3, "by_module": {"libfoo.so": 2, "libbar.so": 1}},
        "crypto": {"hook_keys": {"total": 2, "by_algorithm": {"AES": 2}}, "heap_key_candidates": 1},
        "tls": {"connections": 2, "unique_hosts": ["api.example.com"]},
        "native_strings": {"libfoo.so": ["https://api.example.com/v1"]},
        "assets": {"count": 1, "total_bytes": 1024, "files": ["a.unity3d"]},
        "http": {"requests": 1, "unique_hosts": ["api.example.com"]},
        "sqlite": {"total_ops": 2, "by_op": {"exec": 2}},
        "binder": {"total": 1, "by_type": {"transact": 1}},
        "coverage": {"total_blocks": 99, "top_modules": {"libfoo.so": 99}},
        "dlopen": {"total_loads": 1, "unique_libs": ["/system/lib64/libc.so"]},
        "protobuf": {"total": 1, "by_direction": {"send": 1}},
        "anti_tamper": {"total_bypasses": 1, "bypasses": ["signature-check"]},
        "safetynet": {"total": 1, "by_type": {"attest": 1}},
        "fileio": {"total_ops": 1, "unique_paths": ["/data/data/x/f"]},
        "mono": {"count": 1, "files": ["Assembly-CSharp.dll"]},
        "ue4": {
            "sdk": {
                "classes": 1,
                "functions": 2,
                "class_names": ["AActor"],
                "function_names": ["Tick"],
                "total_objects": 3,
                "total_names": 4,
            },
            "pak_files": [{"path": "/x/a.pak"}],
            "blueprint_trace": {"total_calls": 5, "capped": False, "top_functions": {"Tick": 5}},
        },
        "totally_unknown_section": {"nested": {"a": 1}},
    }
