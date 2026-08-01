"""report — convert report.json into a self-contained HTML research report."""

from __future__ import annotations

import json
import logging
import textwrap
from pathlib import Path

logger = logging.getLogger(__name__)

_CSS = """
body{font-family:system-ui,sans-serif;background:#0f1117;color:#e0e0e0;margin:0;padding:0}
.header{background:#1a1d27;padding:24px 32px;border-bottom:2px solid #2d3045}
.header h1{margin:0;font-size:1.6rem;color:#7eb6ff}
.header .meta{color:#888;font-size:.85rem;margin-top:4px}
.container{max-width:1200px;margin:0 auto;padding:24px 32px}
.section{background:#1a1d27;border:1px solid #2d3045;border-radius:8px;margin-bottom:20px;overflow:hidden}
.section-header{display:flex;align-items:center;gap:10px;padding:14px 18px;background:#1e2130;cursor:pointer;user-select:none}
.section-header h2{margin:0;font-size:1rem;font-weight:600;color:#b0c4f0}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:700;background:#2d3045;color:#aaa}
.badge.high{background:#5c1a1a;color:#ff7070}
.badge.med{background:#4d3800;color:#ffb833}
.badge.low{background:#1a3a1a;color:#6fcf6f}
.badge.info{background:#1a2a40;color:#6ab0ff}
.section-body{padding:18px;display:none}
.section-body.open{display:block}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:8px 10px;background:#222636;color:#8090b0;font-weight:600;border-bottom:1px solid #2d3045}
td{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top;word-break:break-all}
tr:hover td{background:#1e2130}
.mono{font-family:monospace;font-size:.82rem;color:#90d0a0}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.72rem;background:#2d3045;color:#aaa;margin:1px}
.tag.danger{background:#5c1a1a;color:#ff9090}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#1e2130;border:1px solid #2d3045;border-radius:6px;padding:14px 16px}
.stat-card .num{font-size:2rem;font-weight:700;color:#7eb6ff}
.stat-card .lbl{font-size:.8rem;color:#888;margin-top:2px}
pre{background:#0d0f1a;padding:12px;border-radius:6px;overflow:auto;font-size:.8rem;color:#90d0a0;max-height:300px}
"""

_JS = """
document.querySelectorAll('.section-header').forEach(h => {
  h.addEventListener('click', () => {
    h.nextElementSibling.classList.toggle('open');
  });
});
document.querySelectorAll('.section-body[data-open="1"]').forEach(b => b.classList.add('open'));
"""


# ── HTML primitives ───────────────────────────────────────────────────────────


def _badge(level: str, text: str) -> str:
    return f'<span class="badge {level}">{text}</span>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join(f"<tr>{''.join(f'<td>{c}</td>' for c in row)}</tr>" for row in rows)
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"


def _kv_table(data: dict) -> str:
    return _table(["Key", "Count"], [[k, str(v)] for k, v in data.items()])


def _ul(items: list) -> str:
    return "<ul>" + "".join(f"<li class='mono'>{h}</li>" for h in items) + "</ul>"


def _section(title: str, badge_html: str, body_html: str, auto_open: bool = False) -> str:
    open_attr = ' data-open="1"' if auto_open else ""
    return textwrap.dedent(f"""
    <div class="section">
      <div class="section-header">
        <h2>{title}</h2>{badge_html}
      </div>
      <div class="section-body"{open_attr}>{body_html}</div>
    </div>
    """)


# ── Per-section renderers ──────────────────────────────────────────────────────


def _render_dex(data: dict) -> str:
    files = data.get("files", [])
    obf = data.get("obfuscation") or {}
    ratio = obf.get("obfRatioPct", 0)
    verdict = obf.get("verdict", "")
    level = "high" if ratio > 50 else "med" if ratio > 20 else "low"
    badge = _badge(level, f"{ratio}% obfuscated")
    body = f"<p>Files: {', '.join(f'<span class="mono">{f}</span>' for f in files)}</p>"
    body += f"<p>Verdict: <b>{verdict}</b></p>"
    jadx = data.get("jadx") or {}
    if jadx.get("java_files"):
        body += f"<p>jadx decompiled: {jadx['java_files']:,} Java files</p>"
    return _section("DEX Files", badge, body, ratio > 20)


def _render_il2cpp(data: dict) -> str:
    methods = data.get("methods", 0)
    fields = data.get("fields", 0)
    interesting = data.get("interesting_methods", [])
    badge = _badge("info", f"{methods} methods")
    body = f"<p>Methods: {methods:,}  Fields: {fields:,}</p>"
    if interesting:
        rows = [
            [m.get("Name", "?"), m.get("Signature", "?"), m.get("Address", "?")]
            for m in interesting[:50]
        ]
        body += "<p><b>Security-relevant methods:</b></p>"
        body += _table(["Name", "Signature", "Address"], rows)
    return _section("IL2CPP Symbol Map", badge, body, bool(interesting))


def _render_jni(data: dict) -> str:
    total = data.get("total_mappings", 0)
    badge = _badge("info", f"{total} mappings")
    rows = [
        [mod, str(cnt)]
        for mod, cnt in sorted(data.get("by_module", {}).items(), key=lambda x: -x[1])
    ]
    return _section("JNI Map", badge, _table(["Module", "Mappings"], rows), total > 0)


def _render_crypto(data: dict) -> str:
    hk = data.get("hook_keys") or {}
    total = hk.get("total", 0)
    badge = _badge("high" if total > 0 else "low", f"{total} keys hooked")
    body = f"<p>Hook captures: {total}  Heap byte[] candidates: {data.get('heap_key_candidates', 0)}</p>"
    if hk.get("by_algorithm"):
        body += _kv_table(hk["by_algorithm"])
    return _section("Crypto Keys", badge, body, total > 0)


def _render_tls(data: dict) -> str:
    conns = data.get("connections", 0)
    hosts = data.get("unique_hosts", [])
    badge = _badge("info", f"{conns} connections")
    body = f"<p>Unique hosts ({len(hosts)}):</p>" + _ul(hosts)
    return _section("TLS Connections", badge, body, conns > 0)


def _render_native_strings(data: dict) -> str:
    total = sum(len(v) for v in data.values())
    badge = _badge("med" if total > 0 else "low", f"{total} interesting strings")
    rows = [[so, s] for so, strs in data.items() for s in strs[:20]]
    body = _table(["Library", "String"], rows) if rows else "<p>None found.</p>"
    return _section("Native Strings (URLs / JWTs)", badge, body, total > 0)


def _render_assets(data: dict) -> str:
    count = data.get("count", 0)
    badge = _badge("info", f"{count} bundles")
    body = f"<p>Total size: {data.get('total_bytes', 0) / 1024 / 1024:.1f} MB</p>"
    if data.get("files"):
        body += _ul(data["files"])
    return _section("Unity AssetBundles", badge, body)


def _render_http(data: dict) -> str:
    reqs = data.get("requests", 0)
    hosts = data.get("unique_hosts", [])
    badge = _badge("med" if reqs > 0 else "info", f"{reqs} requests")
    body = f"<p>Unique hosts ({len(hosts)}):</p>" + _ul(hosts)
    return _section("HTTP Traffic", badge, body, reqs > 0)


def _render_sqlite(data: dict) -> str:
    total = data.get("total_ops", 0)
    badge = _badge("info", f"{total} ops")
    return _section("SQLite", badge, _kv_table(data.get("by_op", {})), total > 0)


def _render_binder(data: dict) -> str:
    total = data.get("total", 0)
    badge = _badge("info", f"{total} events")
    return _section("Binder / IPC", badge, _kv_table(data.get("by_type", {})), total > 0)


def _render_coverage(data: dict) -> str:
    blocks = data.get("total_blocks", 0)
    badge = _badge("info", f"{blocks} blocks")
    body = f"<p>Total unique basic blocks: {blocks:,}</p>"
    if data.get("top_modules"):
        body += "<p><b>Top modules:</b></p>" + _kv_table(data["top_modules"])
    return _section("Code Coverage", badge, body, blocks > 0)


def _render_dlopen(data: dict) -> str:
    total = data.get("total_loads", 0)
    libs = data.get("unique_libs", [])
    badge = _badge("info", f"{total} loads")
    body = f"<p>Unique libraries ({len(libs)}):</p>" + _ul(libs)
    return _section("dlopen Monitor", badge, body, total > 0)


def _render_protobuf(data: dict) -> str:
    total = data.get("total", 0)
    badge = _badge("info", f"{total} messages")
    return _section("Protobuf", badge, _kv_table(data.get("by_direction", {})), total > 0)


def _render_anti_tamper(data: dict) -> str:
    total = data.get("total_bypasses", 0)
    badge = _badge("med" if total > 0 else "low", f"{total} bypasses")
    bypasses = data.get("bypasses", [])
    body = (
        "<ul>" + "".join(f"<li>{b}</li>" for b in bypasses) + "</ul>"
        if bypasses
        else "<p>None.</p>"
    )
    return _section("Anti-Tamper Bypasses", badge, body, total > 0)


def _render_safetynet(data: dict) -> str:
    total = data.get("total", 0)
    badge = _badge("high" if total > 0 else "low", f"{total} events")
    return _section(
        "SafetyNet / Play Integrity", badge, _kv_table(data.get("by_type", {})), total > 0
    )


def _render_fileio(data: dict) -> str:
    total = data.get("total_ops", 0)
    paths = data.get("unique_paths", [])
    badge = _badge("info", f"{total} ops")
    body = f"<p>Unique paths ({len(paths)}):</p>" + _ul(paths)
    return _section("File I/O", badge, body, total > 0)


def _render_mono(data: dict) -> str:
    count = data.get("count", 0)
    badge = _badge("info", f"{count} DLLs")
    body = _ul(data.get("files", []))
    return _section("Mono DLLs", badge, body)


def _render_ue4(data: dict) -> str:
    sdk = data.get("sdk") or {}
    pak = data.get("pak_files") or []
    bp = data.get("blueprint_trace") or {}

    classes = sdk.get("classes", 0)
    functions = sdk.get("functions", 0)
    badge = _badge("info", f"{classes} classes / {functions} funcs")

    body = ""
    if sdk:
        body += (
            f"<p>Objects: {sdk.get('total_objects', 0):,}  Names: {sdk.get('total_names', 0):,}  "
        )
        body += f"Enums: {sdk.get('enums', 0)}  Structs: {sdk.get('structs', 0)}</p>"
        if sdk.get("class_names"):
            body += "<p><b>Classes (first 50):</b></p>"
            body += _ul(sdk["class_names"][:50])
        if sdk.get("function_names"):
            body += "<p><b>Functions (first 50):</b></p>"
            body += _ul(sdk["function_names"][:50])

    if pak:
        body += f"<p><b>PAK files ({len(pak)}):</b></p>"
        body += _ul([p.get("path", p.get("addr", "?")) for p in pak])

    if bp:
        total = bp.get("total_calls", 0)
        body += f"<p><b>Blueprint trace:</b> {total:,} calls"
        if bp.get("capped"):
            body += " (capped)"
        body += "</p>"
        if bp.get("top_functions"):
            body += "<p><b>Top Blueprint functions:</b></p>"
            body += _kv_table(bp["top_functions"])

    return _section("Unreal Engine 4", badge, body or "<p>No UE4 data.</p>", bool(sdk or pak or bp))


def _render_generic(title: str, data: dict) -> str:
    body = f"<pre>{json.dumps(data, indent=2, ensure_ascii=False)[:4000]}</pre>"
    return _section(title, _badge("info", ""), body)


# ── Renderer dispatch ──────────────────────────────────────────────────────────

_RENDERERS = {
    "dex": _render_dex,
    "il2cpp": _render_il2cpp,
    "jni": _render_jni,
    "crypto": _render_crypto,
    "tls": _render_tls,
    "native_strings": _render_native_strings,
    "assets": _render_assets,
    "http": _render_http,
    "sqlite": _render_sqlite,
    "binder": _render_binder,
    "coverage": _render_coverage,
    "dlopen": _render_dlopen,
    "protobuf": _render_protobuf,
    "anti_tamper": _render_anti_tamper,
    "safetynet": _render_safetynet,
    "fileio": _render_fileio,
    "mono": _render_mono,
    "ue4": _render_ue4,
}

_SKIP_KEYS = {"dump_dir", "tool_versions"}


# ── Summary cards ──────────────────────────────────────────────────────────────


def _summary_cards(report: dict) -> str:
    stats = [
        ("DEX files", len(report.get("dex", {}).get("files", []))),
        ("IL2CPP methods", report.get("il2cpp", {}).get("methods", 0)),
        ("JNI mappings", report.get("jni", {}).get("total_mappings", 0)),
        ("Crypto keys", report.get("crypto", {}).get("hook_keys", {}).get("total", 0)),
        ("TLS hosts", len(report.get("tls", {}).get("unique_hosts", []))),
        ("HTTP requests", report.get("http", {}).get("requests", 0)),
        ("AssetBundles", report.get("assets", {}).get("count", 0)),
        ("Mono DLLs", report.get("mono", {}).get("count", 0)),
        ("Native strings", sum(len(v) for v in report.get("native_strings", {}).values())),
        ("Coverage blocks", report.get("coverage", {}).get("total_blocks", 0)),
        ("SQLite ops", report.get("sqlite", {}).get("total_ops", 0)),
        ("dlopen loads", report.get("dlopen", {}).get("total_loads", 0)),
        ("UE4 classes", report.get("ue4", {}).get("sdk", {}).get("classes", 0)),
        ("UE4 BP calls", report.get("ue4", {}).get("blueprint_trace", {}).get("total_calls", 0)),
    ]
    cards = "".join(
        f'<div class="stat-card"><div class="num">{num}</div><div class="lbl">{lbl}</div></div>'
        for lbl, num in stats
    )
    return f'<div class="summary-grid">{cards}</div>'


# ── Main renderer ──────────────────────────────────────────────────────────────


def generate_html(report: dict, dump_dir: Path) -> str:
    sections = _summary_cards(report)
    for key, data in report.items():
        if key in _SKIP_KEYS:
            continue
        renderer = _RENDERERS.get(key)
        sections += (
            renderer(data) if renderer else _render_generic(key.replace("_", " ").title(), data)
        )

    return textwrap.dedent(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>enma Report — {dump_dir.name}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="header">
    <h1>enma Research Report</h1>
    <div class="meta">Dump: {dump_dir}  |  Generated by enma</div>
  </div>
  <div class="container">
    {sections}
  </div>
  <script>{_JS}</script>
</body>
</html>
""")


def render_report(dump_dir: str, report_json: str | None = None, output: str | None = None) -> str:
    path = Path(dump_dir).resolve()
    json_path = Path(report_json) if report_json else path / "report.json"
    out_path = Path(output) if output else path / "report.html"

    if not json_path.exists():
        raise FileNotFoundError(f"report.json not found: {json_path}")

    report = json.loads(json_path.read_text())
    html = generate_html(report, path)
    out_path.write_text(html, encoding="utf-8")
    logger.info("HTML saved: %s", out_path)
    return str(out_path)
