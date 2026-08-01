"""The registry must never drift from the agents/ tree.

This is the test that pays for the whole suite: the agent list used to be
duplicated in five places, and nothing checked that a registered name had a
matching .js file — or that a new .js file had been registered at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from enma.core.agents import (
    DUMP_AGENTS,
    MEM_AGENTS,
    TAG_DUMP,
    TAG_MEM,
    UE4_AGENTS,
    Agent,
    UnknownAgentError,
    all_agents,
    discover,
    get,
    load_agent,
    names,
)

_ALL = all_agents()


def test_registry_matches_disk_exactly() -> None:
    """Both directions at once: no orphan JS, no phantom registry row."""
    assert {(a.category, a.name) for a in _ALL} == set(discover())


def test_no_unregistered_js_files() -> None:
    """Explicit message for the 'added a JS file, forgot the row' case."""
    orphans = sorted(set(discover()) - {(a.category, a.name) for a in _ALL})
    assert not orphans, f"agent JS on disk but not registered: {orphans}"


@pytest.mark.parametrize("agent", _ALL, ids=lambda a: a.name)
def test_load_agent_returns_nonempty_source(agent: Agent) -> None:
    src = load_agent(agent.name)
    assert src.strip(), f"{agent.filename} is empty"
    assert len(src) > 100


def test_agent_names_are_unique() -> None:
    assert len({a.name for a in _ALL}) == len(_ALL)


def test_tag_subsets_partition_as_documented() -> None:
    """mem agents are deliberately excluded from `dump`'s default set."""
    assert set(UE4_AGENTS) <= set(DUMP_AGENTS)
    assert set(MEM_AGENTS).isdisjoint(DUMP_AGENTS)
    assert set(DUMP_AGENTS) | set(MEM_AGENTS) == {a.name for a in _ALL}


def test_names_preserves_declaration_order() -> None:
    """--help output and dump's load order must be reproducible."""
    assert names() == tuple(a.name for a in _ALL)
    assert names(TAG_DUMP) == DUMP_AGENTS
    assert names(TAG_MEM) == MEM_AGENTS


def test_filename_derives_from_name() -> None:
    assert get("dex").filename == "dex_agent.js"


def test_unknown_agent_raises_unknown_agent_error() -> None:
    with pytest.raises(UnknownAgentError):
        load_agent("does_not_exist")


def test_unknown_agent_error_is_a_key_error() -> None:
    """load_scripts catches it alongside FileNotFoundError."""
    assert issubclass(UnknownAgentError, KeyError)


def test_every_agent_is_documented() -> None:
    """docs/agents.md must not drift from the registry either."""
    doc = Path(__file__).parents[1] / "docs" / "agents.md"
    if not doc.is_file():  # not shipped in the installed package
        pytest.skip("docs/ not present")
    documented = set(re.findall(r"^### `([a-z0-9_]+)`", doc.read_text(), re.MULTILINE))
    assert documented == {a.name for a in _ALL}
