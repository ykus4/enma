"""repack — inject frida-gadget into an APK so it runs on non-rooted devices.

Pipeline:
  1. Download frida-gadget-{version}-android-{arch}.so.xz from GitHub
  2. apktool d  — decode APK
  3. Copy gadget .so into lib/{arch}/
  4. Inject a smali class that calls loadLibrary("frida-gadget") in <clinit>
  5. apktool b  — rebuild APK
  6. zipalign + apksigner / jarsigner — re-sign with a debug key

Requirements (on PATH):
  apktool, apksigner (build-tools) or jarsigner (JDK), keytool, zipalign
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from enma.core.abi import DEFAULT_ABI, arch_to_abi
from enma.core.download import FRIDA_VERSION, cache_dir, download_github_asset

logger = logging.getLogger(__name__)

GADGET_LOADER_CLS = "com/enma/GadgetLoader"

_GADGET_SMALI = """\
.class public {cls};
.super Ljava/lang/Object;

.method static constructor <clinit>()V
    .registers 1
    const-string v0, "frida-gadget"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
"""

_CLINIT_REF = (
    "\n.method static constructor <clinit>()V\n"
    "    .registers 1\n"
    "    sget-object v0, L{cls};->TAG:Ljava/lang/String;\n"
    "    return-void\n"
    ".end method\n"
)


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        logger.error("'%s' not found in PATH.", tool)
        sys.exit(1)
    return path


def _run(*args: str) -> None:
    logger.debug("$ %s", " ".join(args))
    subprocess.run(list(args), check=True)


def _find_signer() -> tuple[str, str]:
    """Return (tool_name, tool_path) for the first available signing tool."""
    for tool in ("apksigner", "jarsigner"):
        path = shutil.which(tool)
        if path:
            return tool, path
    logger.error("Neither apksigner nor jarsigner found.")
    sys.exit(1)


def _ensure_debug_keystore(keystore: Path) -> None:
    if keystore.exists():
        return
    logger.info("Generating debug keystore ...")
    keytool_args = [
        "-genkeypair",
        "-keystore",
        str(keystore),
        "-alias",
        "androiddebugkey",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "10000",
        "-storepass",
        "android",
        "-keypass",
        "android",
        "-dname",
        "CN=Android Debug,O=Android,C=US",
    ]
    _run("keytool", *keytool_args)


def _get_gadget(arch: str) -> Path:
    asset = f"frida-gadget-{FRIDA_VERSION}-android-{arch}.so.xz"
    dest = cache_dir() / f"frida-gadget-{FRIDA_VERSION}-android-{arch}.so"
    download_github_asset(asset, dest, "repack")
    return dest


def _inject_smali(decoded_dir: Path) -> None:
    smali_dirs = sorted(decoded_dir.glob("smali*"))
    if not smali_dirs:
        raise RuntimeError("No smali directory found in decoded APK")

    loader = smali_dirs[0] / f"{GADGET_LOADER_CLS}.smali"
    loader.parent.mkdir(parents=True, exist_ok=True)
    loader.write_text(_GADGET_SMALI.format(cls=GADGET_LOADER_CLS))
    logger.info("Wrote gadget loader: %s", loader)

    patched = 0
    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            text = smali_file.read_text()
            if "Landroid/app/Application;" not in text:
                continue
            if GADGET_LOADER_CLS in text:
                continue
            if ".method static constructor <clinit>()V" not in text:
                text += _CLINIT_REF.format(cls=GADGET_LOADER_CLS)
                smali_file.write_text(text)
                logger.info("Patched Application class: %s", smali_file.name)
                patched += 1
                break

    if patched == 0:
        logger.info("No Application class patched — gadget loads via its own <clinit>")


def _sign_apk(signer: str, signer_path: str, src: Path, dest: Path, keystore: Path) -> None:
    if signer == "apksigner":
        _run(
            signer_path,
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            "pass:android",
            "--key-pass",
            "pass:android",
            "--ks-key-alias",
            "androiddebugkey",
            "--out",
            str(dest),
            str(src),
        )
    else:
        shutil.copy(src, dest)
        _run(
            signer_path,
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-keypass",
            "android",
            str(dest),
            "androiddebugkey",
        )


def repack_apk(
    apk_path: str,
    output_apk: str | None = None,
    arch: str = "arm64",
    keep_workdir: bool = False,
) -> str:
    apk = Path(apk_path).resolve()
    out_apk = Path(output_apk).resolve() if output_apk else apk.with_stem(apk.stem + "-gadget")

    apktool = _require("apktool")
    zipalign = shutil.which("zipalign")
    signer, signer_path = _find_signer()

    abi = arch_to_abi(arch)
    if abi is None:
        logger.warning("Unknown arch '%s', falling back to %s", arch, DEFAULT_ABI)
        abi = DEFAULT_ABI

    gadget_so = _get_gadget(arch)
    keystore = cache_dir() / "debug.keystore"
    _ensure_debug_keystore(keystore)

    with tempfile.TemporaryDirectory(prefix="enma_repack_", delete=not keep_workdir) as tmp:
        tmp_path = Path(tmp)
        decoded = tmp_path / "decoded"
        rebuilt = tmp_path / "rebuilt.apk"
        aligned = tmp_path / "aligned.apk"

        _run(apktool, "d", str(apk), "-o", str(decoded), "-f")

        lib_dir = decoded / "lib" / abi
        lib_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(gadget_so, lib_dir / "libfrida-gadget.so")
        logger.info("Copied gadget to %s/libfrida-gadget.so", lib_dir)

        _inject_smali(decoded)
        _run(apktool, "b", str(decoded), "-o", str(rebuilt))

        if zipalign:
            _run(zipalign, "-f", "-p", "4", str(rebuilt), str(aligned))
        else:
            logger.warning("zipalign not found — skipping alignment")
            shutil.copy(rebuilt, aligned)

        _sign_apk(signer, signer_path, aligned, out_apk, keystore)

        if keep_workdir:
            logger.info("Work directory kept at: %s", tmp)

    logger.info("Done: %s", out_apk)
    return str(out_apk)
