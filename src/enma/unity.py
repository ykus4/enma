"""unity — extract assets from dumped Unity AssetBundle files.

Uses UnityPy (pip install UnityPy) to unpack:
  - Texture2D  → PNG
  - AudioClip  → WAV / OGG
  - TextAsset  → .txt / .bytes
  - MonoBehaviour → JSON (best-effort serialization)
  - Sprite     → PNG

Gracefully reports missing UnityPy instead of crashing the analyze pipeline.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _unitypy_available() -> bool:
    try:
        import importlib

        importlib.import_module("UnityPy")
        return True
    except ImportError:
        return False


def extract_bundles(dump_dir: str, output_dir: str | None = None) -> dict:
    """Extract all .unity3d bundles in *dump_dir* into *output_dir*.

    Returns a summary dict suitable for inclusion in report.json.
    """
    if not _unitypy_available():
        logger.error("UnityPy not installed — run: uv pip install UnityPy")
        return {"error": "UnityPy not installed", "extracted": 0}

    path = Path(dump_dir).resolve()
    out = Path(output_dir).resolve() if output_dir else path / "unity_extracted"
    bundles = list(path.glob("*.unity3d")) + list(path.glob("asset_*.unity3d"))

    if not bundles:
        logger.warning("No .unity3d bundles found.")
        return {"bundles": 0, "extracted": 0}

    import UnityPy  # type: ignore[import]  # ~0.5s to import — only pay for it if there is work

    out.mkdir(parents=True, exist_ok=True)
    summary: dict = {"bundles": len(bundles), "extracted": 0, "by_type": {}, "errors": []}

    for bundle_path in bundles:
        logger.info("Processing %s ...", bundle_path.name)
        try:
            env = UnityPy.load(str(bundle_path))
        except Exception as e:
            summary["errors"].append({"file": bundle_path.name, "error": str(e)})
            continue

        for obj in env.objects:
            type_name = obj.type.name
            summary["by_type"][type_name] = summary["by_type"].get(type_name, 0) + 1
            try:
                _export_object(obj, type_name, bundle_path.stem, out, summary)
            except Exception as e:
                summary["errors"].append(
                    {
                        "file": bundle_path.name,
                        "type": type_name,
                        "error": str(e),
                    }
                )

    logger.info("Extracted %d asset(s) -> %s", summary["extracted"], out)
    return summary


def _export_object(obj: object, type_name: str, bundle_stem: str, out: Path, summary: dict) -> None:
    data = obj.read()  # type: ignore[attr-defined]
    name = getattr(data, "name", None) or f"{bundle_stem}_{type_name}"
    safe = name.replace("/", "_").replace("\\", "_")

    if type_name == "Texture2D":
        img = data.image
        dest = out / f"{safe}.png"
        img.save(str(dest))
        summary["extracted"] += 1

    elif type_name == "AudioClip":
        samples = data.samples
        for sample_name, sample_data in samples.items():
            dest = out / sample_name
            dest.write_bytes(sample_data)
            summary["extracted"] += 1

    elif type_name == "TextAsset":
        text = data.text
        ext = ".txt" if isinstance(text, str) else ".bytes"
        dest = out / f"{safe}{ext}"
        if isinstance(text, str):
            dest.write_text(text, encoding="utf-8")
        else:
            dest.write_bytes(text)
        summary["extracted"] += 1

    elif type_name == "Sprite":
        img = data.image
        dest = out / f"{safe}.png"
        img.save(str(dest))
        summary["extracted"] += 1

    elif type_name == "MonoBehaviour":
        try:
            tree = obj.read_typetree()  # type: ignore[attr-defined]
            dest = out / f"{safe}.json"
            dest.write_text(json.dumps(tree, indent=2, ensure_ascii=False), encoding="utf-8")
            summary["extracted"] += 1
        except Exception:
            pass  # MonoBehaviour without type tree — skip
