"""Android ABI <-> short arch-name translation.

Short names ("arm64") are what the user types and what frida names its release
assets; ABI strings ("arm64-v8a") come from ``ro.product.cpu.abi`` and name the
``lib/<abi>/`` directory inside an APK.

Both lookups return ``None`` for an unknown value — callers apply their own
fallback policy, which differs between ``frida_server`` and ``repack``.
"""

from __future__ import annotations

from typing import Final

_ARCH_TO_ABI: Final[dict[str, str]] = {
    "arm64": "arm64-v8a",
    "arm": "armeabi-v7a",
    "x86_64": "x86_64",
    "x86": "x86",
}
_ABI_TO_ARCH: Final[dict[str, str]] = {abi: arch for arch, abi in _ARCH_TO_ABI.items()}

ARCHES: Final[tuple[str, ...]] = tuple(_ARCH_TO_ABI)
DEFAULT_ARCH: Final = "arm64"
DEFAULT_ABI: Final = _ARCH_TO_ABI[DEFAULT_ARCH]


def abi_to_arch(abi: str) -> str | None:
    """'arm64-v8a' -> 'arm64'. None when unknown."""
    return _ABI_TO_ARCH.get(abi.strip())


def arch_to_abi(arch: str) -> str | None:
    """'arm64' -> 'arm64-v8a'. None when unknown."""
    return _ARCH_TO_ABI.get(arch.strip())
