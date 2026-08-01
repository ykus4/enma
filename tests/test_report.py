from __future__ import annotations

import json
from pathlib import Path

import pytest

from enma.report import _RENDERERS, _SKIP_KEYS, generate_html, render_report


def test_section_count_matches_rendered_keys(sample_report: dict, tmp_path: Path) -> None:
    """Structural rather than string-brittle."""
    html = generate_html(sample_report, tmp_path)
    expected = len(set(sample_report) - _SKIP_KEYS)
    assert html.count('<div class="section">') == expected
    assert html.count('<div class="section-body"') == expected


def test_known_section_titles_render(sample_report: dict, tmp_path: Path) -> None:
    html = generate_html(sample_report, tmp_path)
    assert "<h2>DEX Files</h2>" in html
    assert "<h2>IL2CPP Symbol Map</h2>" in html


def test_skip_keys_are_not_rendered_as_sections(sample_report: dict, tmp_path: Path) -> None:
    html = generate_html(sample_report, tmp_path)
    assert "<h2>Tool Versions</h2>" not in html
    assert "<h2>Dump Dir</h2>" not in html


def test_unknown_key_falls_back_to_generic(tmp_path: Path) -> None:
    html = generate_html({"totally_unknown_section": {"a": 1}}, tmp_path)
    assert "<h2>Totally Unknown Section</h2>" in html
    assert "<pre>" in html
    assert '"a": 1' in html
    assert html.count('<div class="section">') == 1


def test_empty_report_renders_valid_html(tmp_path: Path) -> None:
    html = generate_html({}, tmp_path)
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert html.count("<html") == html.count("</html>") == 1
    assert html.count("<body") == html.count("</body>") == 1
    assert html.count('<div class="section">') == 0
    assert '<div class="summary-grid">' in html


@pytest.mark.parametrize("key", sorted(_RENDERERS))
def test_every_renderer_survives_an_empty_section(key: str, tmp_path: Path) -> None:
    """Exercises every renderer's .get() defaults in one cheap sweep."""
    html = generate_html({key: {}}, tmp_path)
    assert html.count('<div class="section">') == 1


def test_dump_dir_name_appears_in_title(sample_report: dict, tmp_path: Path) -> None:
    html = generate_html(sample_report, tmp_path / "mydump")
    assert "Report — mydump" in html


def test_report_is_branded_enma_not_the_old_name(sample_report: dict, tmp_path: Path) -> None:
    html = generate_html(sample_report, tmp_path)
    assert "androDumper" not in html
    assert "enma Research Report" in html


def test_render_report_writes_html_and_returns_path(sample_report: dict, dump_dir: Path) -> None:
    (dump_dir / "report.json").write_text(json.dumps(sample_report))
    out = render_report(str(dump_dir))
    assert Path(out) == dump_dir / "report.html"
    assert Path(out).read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_render_report_honors_custom_json_and_output(
    sample_report: dict, dump_dir: Path, tmp_path: Path
) -> None:
    src = tmp_path / "elsewhere.json"
    src.write_text(json.dumps(sample_report))
    out = tmp_path / "out.html"
    assert render_report(str(dump_dir), report_json=str(src), output=str(out)) == str(out)
    assert out.exists()


def test_render_report_missing_json_raises(dump_dir: Path) -> None:
    with pytest.raises(FileNotFoundError, match="report.json not found"):
        render_report(str(dump_dir))
