"""Retry-loop semantics, driven with fakes so no device is needed.

This is the one control-flow path in the codebase with genuinely subtle behaviour:
a normal detach must retry, an interrupt must not, and device selection must happen
exactly once no matter how many times the session is re-established.
"""

from __future__ import annotations

import argparse
from typing import Any

import pytest

from enma import dump


@pytest.fixture
def args() -> argparse.Namespace:
    return argparse.Namespace(
        target="com.example",
        serial=None,
        spawn=False,
        watch=False,
        type=["dex"],
        output="./dump",
        retry=False,
        timeout=0,
    )


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch):
    """Replaces every frida touchpoint; records what was called."""
    calls: dict[str, Any] = {"get_device": 0, "open_session": [], "loaded": 0}

    monkeypatch.setattr(
        dump,
        "get_device",
        lambda _serial: calls.__setitem__("get_device", calls["get_device"] + 1) or "DEVICE",
    )
    monkeypatch.setattr(
        dump,
        "open_session",
        lambda device, target, **kw: calls["open_session"].append((device, target)) or "SESSION",
    )
    monkeypatch.setattr(
        dump,
        "load_scripts",
        lambda *a, **kw: calls.__setitem__("loaded", calls["loaded"] + 1) or {},
    )
    monkeypatch.setattr(dump.time, "sleep", lambda _s: None)
    return calls


def _outcomes(monkeypatch: pytest.MonkeyPatch, results: list) -> None:
    """Queue per-attempt results: False=detach, True=interrupt, Exception=raise."""
    it = iter(results)

    def fake(_session: object, **_kw: object) -> bool:
        outcome = next(it)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(dump, "run_until_detached", fake)


def test_device_is_selected_once_across_retries(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: get_device() inside the loop re-prompts on every re-attach."""
    args.retry = True
    _outcomes(monkeypatch, [False, False, True])
    dump.run_dump(args)
    assert harness["get_device"] == 1
    assert len(harness["open_session"]) == 3


def test_normal_detach_retries_when_enabled(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    args.retry = True
    _outcomes(monkeypatch, [False, False, True])
    dump.run_dump(args)
    assert harness["loaded"] == 3


def test_normal_detach_does_not_retry_by_default(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    _outcomes(monkeypatch, [False])
    dump.run_dump(args)
    assert harness["loaded"] == 1


def test_interrupt_breaks_the_retry_loop(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """True means Ctrl+C / timeout — must stop even with --retry."""
    args.retry = True
    _outcomes(monkeypatch, [True])
    dump.run_dump(args)
    assert harness["loaded"] == 1


def test_session_error_is_logged_and_retried(
    args: argparse.Namespace,
    harness: dict,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    args.retry = True
    _outcomes(monkeypatch, [RuntimeError("boom"), True])
    with caplog.at_level("ERROR"):
        dump.run_dump(args)
    assert "boom" in caplog.text
    assert harness["loaded"] == 2


def test_keyboard_interrupt_during_attach_stops_cleanly(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    args.retry = True
    _outcomes(monkeypatch, [KeyboardInterrupt()])
    dump.run_dump(args)  # must not propagate
    assert harness["loaded"] == 1


def test_no_type_runs_the_full_dump_set(
    args: argparse.Namespace, harness: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from enma.core.agents import DUMP_AGENTS

    captured: list[list[str]] = []
    monkeypatch.setattr(
        dump, "load_scripts", lambda _s, agents, *a, **kw: captured.append(agents) or {}
    )
    args.type = None
    _outcomes(monkeypatch, [False])
    dump.run_dump(args)
    assert captured[0] == list(DUMP_AGENTS)
