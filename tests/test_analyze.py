from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from enma import analyze
from enma.analyze import _count_by, _load_json, analyze_dump

# The `write_artifact` fixture from conftest.
WriteArtifact = Callable[[str, object], Path]

# ── helpers ───────────────────────────────────────────────────────────────────


def test_load_json_missing_returns_none(tmp_path: Path) -> None:
    assert _load_json(tmp_path / "nope.json") is None


def test_load_json_reads_list(tmp_path: Path) -> None:
    p = tmp_path / "a.json"
    p.write_text('[{"a": 1}]')
    assert _load_json(p) == [{"a": 1}]


def test_load_json_propagates_decode_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(json.JSONDecodeError):
        _load_json(p)


def test_count_by_tallies() -> None:
    assert _count_by([{"op": "exec"}, {"op": "exec"}, {"op": "q"}], "op") == {"exec": 2, "q": 1}


def test_count_by_missing_key_uses_question_mark() -> None:
    assert _count_by([{}, {"op": "x"}], "op") == {"?": 1, "x": 1}


def test_count_by_empty_list() -> None:
    assert _count_by([], "op") == {}


# ── individual analyzers ──────────────────────────────────────────────────────


def test_analyze_jni(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact(
        "jni_map.json",
        [{"module": "libfoo.so"}, {"module": "libfoo.so"}, {"module": "libbar.so"}],
    )
    report: dict = {}
    analyze._analyze_jni(dump_dir, report)
    assert report["jni"] == {
        "total_mappings": 3,
        "by_module": {"libfoo.so": 2, "libbar.so": 1},
    }


def test_analyze_jni_absent_adds_no_key(dump_dir: Path) -> None:
    report: dict = {}
    analyze._analyze_jni(dump_dir, report)
    assert "jni" not in report


def test_analyze_crypto_always_seeds_its_section(dump_dir: Path) -> None:
    """Documented quirk: crypto is the one section created unconditionally."""
    report: dict = {}
    analyze._analyze_crypto(dump_dir, report)
    assert report["crypto"] == {}


def test_analyze_crypto_counts_keys_and_heap_candidates(
    dump_dir: Path, write_artifact: WriteArtifact
) -> None:
    write_artifact(
        "crypto_keys.json", [{"algorithm": "AES"}, {"algorithm": "AES"}, {"algorithm": "RSA"}]
    )
    write_artifact("heap_bytes.json", [{"addr": "0x1"}, {"addr": "0x2"}])
    report: dict = {}
    analyze._analyze_crypto(dump_dir, report)
    assert report["crypto"]["hook_keys"] == {
        "total": 3,
        "by_algorithm": {"AES": 2, "RSA": 1},
    }
    assert report["crypto"]["heap_key_candidates"] == 2


def test_analyze_http_extracts_unique_hosts(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact(
        "http_traffic.json",
        [
            {"url": "https://api.example.com/v1/a"},
            {"url": "https://api.example.com/v1/b"},
            {"url": "https://cdn.example.net/x"},
        ],
    )
    report: dict = {}
    analyze._analyze_http(dump_dir, report)
    assert report["http"] == {
        "requests": 3,
        "unique_hosts": ["api.example.com", "cdn.example.net"],
    }


def test_analyze_http_tolerates_malformed_url(
    dump_dir: Path, write_artifact: WriteArtifact
) -> None:
    """Regression: url.split('/')[2] used to raise IndexError here."""
    write_artifact("http_traffic.json", [{"url": "malformed-no-scheme"}])
    report: dict = {}
    analyze._analyze_http(dump_dir, report)
    assert report["http"] == {"requests": 1, "unique_hosts": ["?"]}


def test_analyze_tls_dedupes_sni(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("tls_connections.json", [{"sni": "a.com"}, {"sni": "a.com"}, {"sni": ""}, {}])
    report: dict = {}
    analyze._analyze_tls(dump_dir, report)
    assert report["tls"] == {"connections": 4, "unique_hosts": ["a.com"]}


def test_analyze_coverage_caps_top_modules_at_10(
    dump_dir: Path, write_artifact: WriteArtifact
) -> None:
    write_artifact(
        "coverage.json", {"totalBlocks": 500, "summary": {f"lib{i}.so": i for i in range(15)}}
    )
    report: dict = {}
    analyze._analyze_coverage(dump_dir, report)
    assert report["coverage"]["total_blocks"] == 500
    assert len(report["coverage"]["top_modules"]) == 10
    assert next(iter(report["coverage"]["top_modules"])) == "lib14.so"


def test_analyze_sqlite_by_op(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("sqlite_log.json", [{"op": "exec"}, {"op": "query"}, {"op": "exec"}])
    report: dict = {}
    analyze._analyze_sqlite(dump_dir, report)
    assert report["sqlite"] == {"total_ops": 3, "by_op": {"exec": 2, "query": 1}}


def test_analyze_binder_by_type(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("binder_log.json", [{"type": "transact"}, {"type": "reply"}])
    report: dict = {}
    analyze._analyze_binder(dump_dir, report)
    assert report["binder"] == {"total": 2, "by_type": {"transact": 1, "reply": 1}}


def test_analyze_protobuf_by_direction(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("protobuf_log.json", [{"direction": "send"}, {"direction": "recv"}])
    report: dict = {}
    analyze._analyze_protobuf(dump_dir, report)
    assert report["protobuf"]["total"] == 2


def test_analyze_safetynet_by_type(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("safetynet_log.json", [{"type": "attest"}])
    report: dict = {}
    analyze._analyze_safetynet(dump_dir, report)
    assert report["safetynet"] == {"total": 1, "by_type": {"attest": 1}}


def test_analyze_dlopen_filters_null_paths(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact(
        "dlopen_log.json",
        [{"path": "/a/libc.so"}, {"path": "<null>"}, {"path": "?"}, {"path": "/a/libc.so"}],
    )
    report: dict = {}
    analyze._analyze_dlopen(dump_dir, report)
    assert report["dlopen"] == {"total_loads": 4, "unique_libs": ["/a/libc.so"]}


def test_analyze_anti_tamper_caps_bypass_list_at_50(
    dump_dir: Path, write_artifact: WriteArtifact
) -> None:
    write_artifact("anti_tamper_log.json", [{"bypass": f"b{i}"} for i in range(60)])
    report: dict = {}
    analyze._analyze_anti_tamper(dump_dir, report)
    assert report["anti_tamper"]["total_bypasses"] == 60
    assert len(report["anti_tamper"]["bypasses"]) == 50


def test_analyze_fileio_caps_paths_at_50(dump_dir: Path, write_artifact: WriteArtifact) -> None:
    write_artifact("fileio_log.json", [{"path": f"/p/{i}"} for i in range(60)])
    report: dict = {}
    analyze._analyze_fileio(dump_dir, report)
    assert report["fileio"]["total_ops"] == 60
    assert len(report["fileio"]["unique_paths"]) == 50


def test_analyze_dex_without_jadx_still_records_files(dump_dir: Path) -> None:
    (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00")
    report: dict = {}
    analyze._analyze_dex(dump_dir, report)
    assert report["dex"]["files"] == ["classes.dex"]
    assert report["dex"]["jadx"] is None


def test_analyze_native_strings_finds_urls_and_jwts(
    dump_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (dump_dir / "libfoo.so").write_bytes(b"\x7fELF")
    monkeypatch.setattr(analyze, "_find", lambda t: "/usr/bin/strings" if t == "strings" else None)
    monkeypatch.setattr(
        analyze,
        "_run",
        lambda *a, **k: (
            0,
            "https://api.example.com/v1/login\n"
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig\n",
            "",
        ),
    )
    report: dict = {}
    analyze._analyze_native_strings(dump_dir, report)
    assert len(report["native_strings"]["libfoo.so"]) == 2


def test_analyze_ue4_reads_all_three_artifacts(
    dump_dir: Path, write_artifact: WriteArtifact
) -> None:
    write_artifact("ue4_sdk.json", {"stats": {"classes": 7, "functions": 9}, "classes": ["AActor"]})
    write_artifact("ue4_pak_list.json", [{"path": "/x/a.pak"}])
    write_artifact(
        "ue4_blueprint_trace.json",
        {"total": 3, "entries": [{"func": "Tick"}, {"func": "Tick"}, {"func": "Beg"}]},
    )
    report: dict = {}
    analyze._analyze_ue4(dump_dir, report)
    assert report["ue4"]["sdk"]["classes"] == 7
    assert report["ue4"]["pak_files"] == [{"path": "/x/a.pak"}]
    assert report["ue4"]["blueprint_trace"]["top_functions"] == {"Tick": 2, "Beg": 1}


def test_analyze_ue4_absent_adds_no_key(dump_dir: Path) -> None:
    report: dict = {}
    analyze._analyze_ue4(dump_dir, report)
    assert "ue4" not in report


# ── end-to-end graceful degradation ───────────────────────────────────────────


def test_analyze_dump_on_empty_dir_writes_valid_report(dump_dir: Path) -> None:
    """Degrading gracefully on a dump with nothing in it is a documented property."""
    analyze_dump(str(dump_dir))
    report = json.loads((dump_dir / "report.json").read_text())
    assert set(report) == {"dump_dir", "tool_versions", "crypto"}
    assert report["tool_versions"] == {"jadx": None, "apktool": None}


def test_analyze_dump_custom_output_path(dump_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "custom.json"
    analyze_dump(str(dump_dir), output=str(out))
    assert json.loads(out.read_text())["dump_dir"] == str(dump_dir.resolve())


def test_analyze_dump_missing_dir_exits_1(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        analyze_dump(str(tmp_path / "nope"))
    assert exc.value.code == 1


def test_analyze_dump_runs_every_registered_analyzer(
    dump_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[str] = []
    stubs = [(lambda _d, _r, n=fn.__name__: called.append(n)) for fn in analyze._ANALYZERS]
    monkeypatch.setattr(analyze, "_ANALYZERS", stubs)
    analyze_dump(str(dump_dir))
    assert len(called) == len(stubs)
