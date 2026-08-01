"""Single source of truth for the JS agents shipped under ``enma/agents/``.

Adding a new agent means dropping ``agents/<category>/<name>_agent.js`` in place
and adding **one row** to ``_AGENTS`` below. ``tests/test_agents.py`` asserts the
table and the filesystem agree in both directions, so a forgotten row fails CI
rather than surfacing as a runtime error.

The table is declarative rather than discovered from disk because argparse needs
a deterministic, ordered list at parser-build time, and because the filesystem
cannot express the two things that actually vary: whether an agent is part of
bare ``dump``'s default set, and whether the ``ue4`` subcommand offers it.

This module must stay frida-free — ``cli`` imports it eagerly to build ``--help``.
"""

from __future__ import annotations

import importlib.resources
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from typing import Final

AGENTS_PACKAGE: Final = "enma.agents"

# Tags express membership, not location. An agent may carry several.
TAG_DUMP: Final = "dump"  # included when `enma dump` runs with no -t
TAG_UE4: Final = "ue4"  # offered by the `enma ue4` subcommand
TAG_MEM: Final = "mem"  # RPC-only, driven by memscan / mempatch


class UnknownAgentError(KeyError):
    """Raised when an agent name is not in the registry."""


@dataclass(frozen=True, slots=True)
class Agent:
    name: str  # -> agents/<category>/<name>_agent.js
    category: str  # subdirectory under agents/
    tags: frozenset[str]

    @property
    def filename(self) -> str:
        return f"{self.name}_agent.js"


def _a(name: str, category: str, *tags: str) -> Agent:
    return Agent(name=name, category=category, tags=frozenset(tags))


# Declaration order is public API: it drives --help ordering and the order in
# which `dump` loads scripts.
_AGENTS: Final[tuple[Agent, ...]] = (
    # core dump
    _a("dex", "dump", TAG_DUMP),
    _a("il2cpp", "dump", TAG_DUMP),
    _a("assets", "dump", TAG_DUMP),
    _a("mono", "dump", TAG_DUMP),
    _a("ssl", "bypass", TAG_DUMP),
    _a("crypto", "bypass", TAG_DUMP),
    _a("jni", "analysis", TAG_DUMP),
    _a("heap", "dump", TAG_DUMP),
    # dynamic analysis
    _a("coverage", "analysis", TAG_DUMP),
    _a("tracer", "analysis", TAG_DUMP),
    _a("binder", "network", TAG_DUMP),
    # bypass
    _a("anti_detect", "bypass", TAG_DUMP),
    _a("anti_tamper", "bypass", TAG_DUMP),
    _a("safetynet", "bypass", TAG_DUMP),
    # protocol / storage
    _a("http", "network", TAG_DUMP),
    _a("websocket", "network", TAG_DUMP),
    _a("protobuf", "network", TAG_DUMP),
    _a("sqlite", "storage", TAG_DUMP),
    _a("fileio", "storage", TAG_DUMP),
    _a("dlopen", "storage", TAG_DUMP),
    # Unreal Engine — dumpable and also exposed via the `ue4` subcommand
    _a("ue4_sdk", "ue4", TAG_DUMP, TAG_UE4),
    _a("ue4_pak", "ue4", TAG_DUMP, TAG_UE4),
    _a("ue4_blueprint", "ue4", TAG_DUMP, TAG_UE4),
    # interactive memory — RPC-only, deliberately not dumpable
    _a("memscan", "mem", TAG_MEM),
    _a("mempatch", "mem", TAG_MEM),
)

_BY_NAME: Final[dict[str, Agent]] = {a.name: a for a in _AGENTS}


def all_agents() -> tuple[Agent, ...]:
    return _AGENTS


def get(name: str) -> Agent:
    try:
        return _BY_NAME[name]
    except KeyError:
        raise UnknownAgentError(name) from None


def names(tag: str | None = None) -> tuple[str, ...]:
    """Agent names in declaration order, optionally filtered by *tag*."""
    return tuple(a.name for a in _AGENTS if tag is None or tag in a.tags)


DUMP_AGENTS: Final[tuple[str, ...]] = names(TAG_DUMP)
UE4_AGENTS: Final[tuple[str, ...]] = names(TAG_UE4)
MEM_AGENTS: Final[tuple[str, ...]] = names(TAG_MEM)


@cache
def load_agent(name: str) -> str:
    """Return the JS source for *name*.

    Raises ``UnknownAgentError`` for an unregistered name, ``FileNotFoundError``
    when the .js is missing from the installed package.
    """
    agent = get(name)
    ref = (
        importlib.resources.files(AGENTS_PACKAGE).joinpath(agent.category).joinpath(agent.filename)
    )
    return ref.read_text(encoding="utf-8")


def discover() -> Iterator[tuple[str, str]]:
    """Yield ``(category, agent_name)`` for every ``*_agent.js`` on disk.

    Used by the tests to assert the registry has not drifted from the tree.
    """
    root = importlib.resources.files(AGENTS_PACKAGE)
    for entry in root.iterdir():
        if not entry.is_dir() or entry.name.startswith(("_", ".")):
            continue
        for f in entry.iterdir():
            if f.name.endswith("_agent.js"):
                yield entry.name, f.name.removesuffix("_agent.js")
