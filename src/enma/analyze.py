"""analyze — post-dump analysis pipeline.

Runs external tools (jadx, apktool, Il2CppDumper) on the files in a dump
directory and produces a consolidated report.json.

External tools (all optional — analysis degrades gracefully if missing):
  jadx        : https://github.com/skylot/jadx
  apktool     : https://apktool.org
  il2cppdumper: https://github.com/Perfare/Il2CppDumper  (CLI version)
  strings     : standard Unix utility (or strings.exe on Windows)
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _find(tool: str) -> str | None:
    return shutil.which(tool)


def _run(
    *args: str,
    capture: bool = True,
    cwd: str | None = None,
    timeout: int = 300,
) -> tuple[int, str, str]:
    result = subprocess.run(
        list(args),
        capture_output=capture,
        text=True,
        cwd=cwd,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _load_json(path: Path) -> list | dict | None:
    """Return parsed JSON from *path*, or None if absent."""
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _count_by(data: list, key: str) -> dict:
    """Tally occurrences of data[i][key] across a list of dicts."""
    tally: dict = {}
    for entry in data:
        k = entry.get(key, "?")
        tally[k] = tally.get(k, 0) + 1
    return tally


# ── DEX analysis via jadx ─────────────────────────────────────────────────────


def _analyze_dex(dump_dir: Path, report: dict) -> None:
    dex_files = sorted(dump_dir.glob("*.dex"))
    if not dex_files:
        return

    report["dex"] = {"files": [f.name for f in dex_files], "jadx": None, "obfuscation": None}

    obf = _load_json(dump_dir / "dex_obfuscation_report.json")
    if obf:
        report["dex"]["obfuscation"] = obf

    jadx = _find("jadx")
    if not jadx:
        logger.warning("jadx not found — skipping DEX decompilation")
        return

    out_dir = dump_dir / "jadx_out"
    logger.info("Running jadx on %d DEX file(s) -> %s", len(dex_files), out_dir)
    rc, _, stderr = _run(
        jadx,
        "--output-dir",
        str(out_dir),
        "--threads-count",
        "4",
        *[str(f) for f in dex_files],
        capture=True,
        timeout=600,
    )
    report["dex"]["jadx"] = {
        "exit_code": rc,
        "output_dir": str(out_dir),
        "error": stderr[:2000] if rc != 0 else None,
    }
    if rc == 0:
        java_files = list(out_dir.rglob("*.java"))
        report["dex"]["jadx"]["java_files"] = len(java_files)
        logger.info("jadx: %d Java files decompiled", len(java_files))
    else:
        logger.error("jadx failed (exit %d)", rc)


# ── IL2CPP analysis ───────────────────────────────────────────────────────────


def _analyze_il2cpp(dump_dir: Path, report: dict) -> None:
    il2cpp_so = dump_dir / "libil2cpp.so"
    metadata = dump_dir / "global-metadata.dat"
    dump_json = dump_dir / "il2cpp_dump.json"

    if not il2cpp_so.exists() and not dump_json.exists():
        return

    section: dict = {
        "libil2cpp_size": il2cpp_so.stat().st_size if il2cpp_so.exists() else None,
        "metadata_size": metadata.stat().st_size if metadata.exists() else None,
    }
    report["il2cpp"] = section

    data = _load_json(dump_json)
    if data:
        section["methods"] = len(data.get("ScriptMethod", []))
        section["fields"] = len(data.get("ScriptMetadata", []))
        logger.info("IL2CPP: %d methods, %d fields", section["methods"], section["fields"])

        keywords = re.compile(
            r"(auth|login|token|secret|key|password|encrypt|decrypt|hash|sign|verify)",
            re.IGNORECASE,
        )
        interesting = [
            m for m in data.get("ScriptMethod", []) if keywords.search(m.get("Name", ""))
        ]
        section["interesting_methods"] = interesting[:50]
        if interesting:
            logger.info("IL2CPP: %d security-related method(s) flagged", len(interesting))

    il2cpp_dumper = _find("Il2CppDumper") or _find("il2cppdumper")
    if il2cpp_dumper and il2cpp_so.exists() and metadata.exists():
        out_dir = dump_dir / "il2cppdumper_out"
        out_dir.mkdir(exist_ok=True)
        logger.info("Running Il2CppDumper -> %s", out_dir)
        rc, _, _ = _run(il2cpp_dumper, str(il2cpp_so), str(metadata), str(out_dir), timeout=120)
        section["il2cppdumper"] = {"exit_code": rc, "output_dir": str(out_dir)}


# ── JNI map analysis ──────────────────────────────────────────────────────────


def _analyze_jni(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "jni_map.json")
    if data is None:
        return

    modules: dict = {}
    for entry in data:
        mod = entry.get("module", "?")
        modules[mod] = modules.get(mod, 0) + 1

    report["jni"] = {"total_mappings": len(data), "by_module": modules}
    logger.info("JNI: %d mappings across %d module(s)", len(data), len(modules))


# ── Crypto key analysis ───────────────────────────────────────────────────────


def _analyze_crypto(dump_dir: Path, report: dict) -> None:
    section: dict = {}
    report["crypto"] = section

    keys = _load_json(dump_dir / "crypto_keys.json")
    if keys is not None:
        section["hook_keys"] = {"total": len(keys), "by_algorithm": _count_by(keys, "algorithm")}
        logger.info("Crypto hooks: %d key event(s)", len(keys))

    byte_cands = _load_json(dump_dir / "heap_bytes.json")
    if byte_cands is not None:
        section["heap_key_candidates"] = len(byte_cands)
        logger.info("Heap: %d high-entropy byte[] candidate(s)", len(byte_cands))


# ── AssetBundle listing ───────────────────────────────────────────────────────


def _analyze_assets(dump_dir: Path, report: dict) -> None:
    bundles = list(dump_dir.glob("*.unity3d")) + list(dump_dir.glob("asset_*.unity3d"))
    if not bundles:
        return
    report["assets"] = {
        "count": len(bundles),
        "total_bytes": sum(f.stat().st_size for f in bundles),
        "files": [f.name for f in bundles],
    }
    logger.info("Assets: %d bundle(s)", len(bundles))


# ── Mono DLL analysis ─────────────────────────────────────────────────────────


def _analyze_mono(dump_dir: Path, report: dict) -> None:
    dlls = list(dump_dir.glob("*.dll"))
    if not dlls:
        return

    report["mono"] = {"count": len(dlls), "files": [f.name for f in dlls]}
    logger.info("Mono: %d DLL(s)", len(dlls))

    jadx = _find("jadx")
    if not jadx:
        return

    out_dir = dump_dir / "jadx_mono_out"
    logger.info("Running jadx on %d DLL(s) -> %s", len(dlls), out_dir)
    rc, _, _ = _run(jadx, "--output-dir", str(out_dir), *[str(d) for d in dlls], timeout=600)
    report["mono"]["jadx"] = {"exit_code": rc, "output_dir": str(out_dir)}


# ── strings extraction ────────────────────────────────────────────────────────


def _analyze_native_strings(dump_dir: Path, report: dict) -> None:
    so_files = list(dump_dir.glob("lib*.so"))
    if not so_files:
        return

    strings_bin = _find("strings")
    if not strings_bin:
        return

    url_re = re.compile(r"https?://[^\s\"'<>]{8,}")
    jwt_re = re.compile(r"ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
    all_interesting: dict[str, list[str]] = {}

    for so in so_files:
        rc, out, _ = _run(strings_bin, "-n", "6", str(so), timeout=30)
        if rc != 0:
            continue
        text = "\n".join(out.splitlines())
        interesting = url_re.findall(text) + jwt_re.findall(text)
        if interesting:
            all_interesting[so.name] = interesting[:100]

    if all_interesting:
        report["native_strings"] = all_interesting
        total = sum(len(v) for v in all_interesting.values())
        so_count = len(all_interesting)
        logger.info("Native strings: %d URL/JWT found across %d .so file(s)", total, so_count)


# ── TLS log analysis ──────────────────────────────────────────────────────────


def _analyze_tls(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "tls_connections.json")
    if data is None:
        return
    hosts = sorted({e.get("sni", "") for e in data if e.get("sni")})
    report["tls"] = {"connections": len(data), "unique_hosts": hosts}
    logger.info("TLS: %d connections to %d unique host(s)", len(data), len(hosts))


# ── New agent outputs ─────────────────────────────────────────────────────────


def _analyze_http(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "http_traffic.json")
    if data is None:
        return
    hosts = sorted({urlparse(e["url"]).netloc or "?" for e in data if e.get("url")})
    report["http"] = {"requests": len(data), "unique_hosts": hosts}
    logger.info("HTTP: %d request(s) to %d host(s)", len(data), len(hosts))


def _analyze_sqlite(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "sqlite_log.json")
    if data is None:
        return
    report["sqlite"] = {"total_ops": len(data), "by_op": _count_by(data, "op")}
    logger.info("SQLite: %d operation(s)", len(data))


def _analyze_binder(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "binder_log.json")
    if data is None:
        return
    report["binder"] = {"total": len(data), "by_type": _count_by(data, "type")}
    logger.info("Binder: %d event(s)", len(data))


def _analyze_coverage(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "coverage.json")
    if data is None:
        return
    summary = data.get("summary", {})
    top = dict(sorted(summary.items(), key=lambda x: -x[1])[:10])
    report["coverage"] = {"total_blocks": data.get("totalBlocks", 0), "top_modules": top}
    logger.info("Coverage: %d unique basic blocks", data.get("totalBlocks", 0))


def _analyze_dlopen(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "dlopen_log.json")
    if data is None:
        return
    libs = sorted({e.get("path", "?") for e in data if e.get("path") not in ("<null>", "?", None)})
    report["dlopen"] = {"total_loads": len(data), "unique_libs": libs}
    logger.info("dlopen: %d load(s), %d unique lib(s)", len(data), len(libs))


def _analyze_protobuf(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "protobuf_log.json")
    if data is None:
        return
    report["protobuf"] = {"total": len(data), "by_direction": _count_by(data, "direction")}
    logger.info("Protobuf: %d message(s)", len(data))


def _analyze_anti_tamper(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "anti_tamper_log.json")
    if data is None:
        return
    bypasses = [e.get("bypass", "?") for e in data]
    report["anti_tamper"] = {"total_bypasses": len(bypasses), "bypasses": bypasses[:50]}
    logger.info("Anti-tamper: %d detection bypass(es) triggered", len(bypasses))


def _analyze_safetynet(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "safetynet_log.json")
    if data is None:
        return
    report["safetynet"] = {"total": len(data), "by_type": _count_by(data, "type")}
    logger.info("SafetyNet: %d attestation event(s)", len(data))


def _analyze_fileio(dump_dir: Path, report: dict) -> None:
    data = _load_json(dump_dir / "fileio_log.json")
    if data is None:
        return
    paths = sorted({e.get("path", "?") for e in data if e.get("path")})
    report["fileio"] = {"total_ops": len(data), "unique_paths": paths[:50]}
    logger.info("File I/O: %d operation(s) on %d path(s)", len(data), len(paths))


# ── UE4 analysis ──────────────────────────────────────────────────────────────


def _analyze_ue4(dump_dir: Path, report: dict) -> None:
    from enma.ue4 import analyze_ue4_dump

    analyze_ue4_dump(dump_dir, report)


# ── Main entry ────────────────────────────────────────────────────────────────

_ANALYZERS = [
    _analyze_dex,
    _analyze_il2cpp,
    _analyze_jni,
    _analyze_crypto,
    _analyze_assets,
    _analyze_mono,
    _analyze_native_strings,
    _analyze_tls,
    _analyze_http,
    _analyze_sqlite,
    _analyze_binder,
    _analyze_coverage,
    _analyze_dlopen,
    _analyze_protobuf,
    _analyze_anti_tamper,
    _analyze_safetynet,
    _analyze_fileio,
    _analyze_ue4,
]


def analyze_dump(dump_dir: str, output: str | None = None) -> None:
    path = Path(dump_dir).resolve()
    if not path.is_dir():
        logger.error("Directory not found: %s", path)
        sys.exit(1)

    logger.info("Analyzing dump: %s", path)
    report: dict = {
        "dump_dir": str(path),
        "tool_versions": {
            "jadx": _run("jadx", "--version")[1].strip() if _find("jadx") else None,
            "apktool": _run("apktool", "--version")[1].strip() if _find("apktool") else None,
        },
    }

    for fn in _ANALYZERS:
        fn(path, report)

    out_path = Path(output) if output else path / "report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    logger.info("Report saved: %s", out_path)
