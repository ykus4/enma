from __future__ import annotations

import pytest

from enma.core.abi import (
    ARCHES,
    DEFAULT_ABI,
    DEFAULT_ARCH,
    abi_to_arch,
    arch_to_abi,
)


@pytest.mark.parametrize(
    ("arch", "abi"),
    [("arm64", "arm64-v8a"), ("arm", "armeabi-v7a"), ("x86_64", "x86_64"), ("x86", "x86")],
)
def test_arch_abi_round_trip(arch: str, abi: str) -> None:
    assert arch_to_abi(arch) == abi
    assert abi_to_arch(abi) == arch


def test_every_arch_round_trips() -> None:
    for arch in ARCHES:
        assert abi_to_arch(arch_to_abi(arch)) == arch


def test_unknown_values_return_none() -> None:
    """Callers apply their own fallback, so the table itself must not guess."""
    assert arch_to_abi("riscv") is None
    assert abi_to_arch("mips64") is None
    assert arch_to_abi("") is None


def test_getprop_output_is_stripped() -> None:
    """_device_arch feeds raw adb stdout straight in."""
    assert abi_to_arch("arm64-v8a\n") == "arm64"


def test_defaults_are_consistent() -> None:
    assert arch_to_abi(DEFAULT_ARCH) == DEFAULT_ABI
    assert DEFAULT_ARCH in ARCHES


def test_cli_arch_choices_match_the_table() -> None:
    """The parser used to hardcode a 5th copy of this list."""
    from enma.cli import _build_parser

    parser = _build_parser()
    sub = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
    repack = sub.choices["repack"]
    arch_action = next(a for a in repack._actions if a.dest == "arch")
    assert set(arch_action.choices) == set(ARCHES)
    assert arch_action.default == DEFAULT_ARCH
