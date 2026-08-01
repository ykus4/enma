from __future__ import annotations

import argparse

import pytest

from enma.cli import _DISPATCH, _build_parser


@pytest.fixture
def parser() -> argparse.ArgumentParser:
    return _build_parser()


def _subparsers(p: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))


def test_every_dispatch_entry_has_a_parser(parser: argparse.ArgumentParser) -> None:
    assert set(_DISPATCH) == set(_subparsers(parser).choices)


def test_every_dispatch_target_is_callable() -> None:
    assert all(callable(fn) for fn in _DISPATCH.values())


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (
            ["dump", "com.x"],
            {
                "command": "dump",
                "target": "com.x",
                "type": None,
                "output": "./dump",
                "spawn": False,
                "watch": False,
                "retry": False,
                "timeout": 0,
            },
        ),
        (
            ["dump", "com.x", "-t", "dex", "ssl", "-o", "/o", "--spawn", "--timeout", "30"],
            {"type": ["dex", "ssl"], "output": "/o", "spawn": True, "timeout": 30},
        ),
        (["list", "-s", "emulator-5554"], {"command": "list", "serial": "emulator-5554"}),
        (["setup", "-f"], {"command": "setup", "force": True}),
        (
            ["repack", "a.apk", "--arch", "x86_64"],
            {"command": "repack", "apk": "a.apk", "arch": "x86_64", "keep_workdir": False},
        ),
        (["analyze", "/d"], {"command": "analyze", "dump_dir": "/d", "output": None}),
        (["report", "/d", "--json", "r.json"], {"command": "report", "json": "r.json"}),
        (["unity", "/d", "-o", "/out"], {"command": "unity", "output": "/out"}),
        (
            ["ue4", "com.x", "-t", "ue4_pak", "--extract-pak"],
            {"command": "ue4", "type": ["ue4_pak"], "extract_pak": True},
        ),
        (["memscan", "com.x", "--watch"], {"command": "memscan", "watch": True}),
        (
            ["mempatch", "com.x", "0xdead", "-t", "float", "-v", "1.5"],
            {"command": "mempatch", "addr": "0xdead", "type": "float", "value": "1.5"},
        ),
        (["mempatch", "com.x", "0xdead", "--bytes", "DE", "AD"], {"bytes": ["DE", "AD"]}),
    ],
)
def test_argv_parses_to_expected_namespace(
    parser: argparse.ArgumentParser, argv: list[str], expected: dict
) -> None:
    ns = parser.parse_args(argv)
    for key, value in expected.items():
        assert getattr(ns, key) == value, key


def test_invalid_agent_type_exits_2(parser: argparse.ArgumentParser) -> None:
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dump", "com.x", "-t", "not_an_agent"])
    assert exc.value.code == 2


def test_dump_type_choices_are_registered_dump_agents(parser: argparse.ArgumentParser) -> None:
    from enma.core.agents import DUMP_AGENTS

    dump = _subparsers(parser).choices["dump"]
    action = next(a for a in dump._actions if a.dest == "type")
    assert tuple(action.choices) == DUMP_AGENTS


def test_ue4_type_choices_are_ue4_agents(parser: argparse.ArgumentParser) -> None:
    from enma.core.agents import UE4_AGENTS

    ue4 = _subparsers(parser).choices["ue4"]
    action = next(a for a in ue4._actions if a.dest == "type")
    assert tuple(action.choices) == UE4_AGENTS


def test_dump_requires_target(parser: argparse.ArgumentParser) -> None:
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dump"])
    assert exc.value.code == 2


def test_no_args_yields_command_none(parser: argparse.ArgumentParser) -> None:
    ns = parser.parse_args([])
    assert ns.command is None
    assert _DISPATCH.get(ns.command) is None


def test_main_with_no_args_prints_help(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from enma import cli

    monkeypatch.setattr("sys.argv", ["enma"])
    cli.main()
    out = capsys.readouterr().out
    assert "usage:" in out
    assert "dump" in out


# ── target quartet: every target-taking command satisfies core.session.TargetArgs
@pytest.mark.parametrize(
    ("command", "argv"),
    [
        ("dump", ["dump", "com.x"]),
        ("ue4", ["ue4", "com.x"]),
        ("memscan", ["memscan", "com.x"]),
        ("mempatch", ["mempatch", "com.x", "0x1"]),
    ],
)
def test_target_commands_expose_the_target_args_protocol(
    parser: argparse.ArgumentParser, command: str, argv: list[str]
) -> None:
    ns = parser.parse_args(argv)
    for attr in ("target", "serial", "spawn", "watch"):
        assert hasattr(ns, attr), f"{command} is missing {attr}"


# ── -v placement (behaviour fixed during the core/ refactor) ──────────────────
def test_verbose_accepted_before_subcommand(parser: argparse.ArgumentParser) -> None:
    assert parser.parse_args(["-v", "dump", "com.x"]).verbose is True


def test_verbose_accepted_after_subcommand(parser: argparse.ArgumentParser) -> None:
    """Used to exit 2 — only `enma -v dump` worked."""
    assert parser.parse_args(["dump", "com.x", "-v"]).verbose is True


def test_verbose_absent_when_not_given(parser: argparse.ArgumentParser) -> None:
    """SUPPRESS keeps subparser defaults from clobbering the root flag."""
    ns = parser.parse_args(["dump", "com.x"])
    assert not hasattr(ns, "verbose")
    assert getattr(ns, "verbose", False) is False


def test_mempatch_short_v_stays_value_not_verbose(parser: argparse.ArgumentParser) -> None:
    """mempatch owns -v for --value, so it gets --verbose long-form only."""
    ns = parser.parse_args(["mempatch", "com.x", "0x1", "-v", "5"])
    assert ns.value == "5"
    assert not hasattr(ns, "verbose")


def test_mempatch_long_verbose_works(parser: argparse.ArgumentParser) -> None:
    assert parser.parse_args(["mempatch", "com.x", "0x1", "--verbose"]).verbose is True
