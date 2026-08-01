# Development

## Project layout

```
enma/
├── pyproject.toml
├── docs/                       # this site
├── tests/                      # offline test suite — no device required
└── src/enma/
    ├── cli.py                  # argument parser + dispatch ONLY
    ├── core/                   # shared primitives
    │   ├── agents.py           #   the agent registry + load_agent()
    │   ├── session.py          #   frida device / session lifecycle
    │   ├── download.py         #   GitHub release download + cache
    │   └── abi.py              #   Android ABI <-> arch translation
    ├── dump.py                 # `dump` and `list`
    ├── frida_server.py         # frida-server auto-deploy (`setup`)
    ├── repack.py               # frida-gadget APK injection
    ├── analyze.py              # post-dump analysis pipeline
    ├── report.py               # HTML report generation
    ├── unity.py                # Unity AssetBundle extraction
    ├── mem.py                  # memscan / mempatch
    ├── ue4.py                  # UE4 runtime analysis
    └── agents/
        ├── dump/               # dex, il2cpp, assets, mono, heap
        ├── analysis/           # coverage, tracer, jni
        ├── bypass/             # ssl, crypto, anti_detect, anti_tamper, safetynet
        ├── network/            # http, websocket, protobuf, binder
        ├── storage/            # sqlite, fileio, dlopen
        ├── ue4/                # ue4_sdk, ue4_pak, ue4_blueprint
        └── mem/                # memscan, mempatch
```

### Layering rule

Dependencies flow in one direction only:

```
cli.py  ──►  feature modules  ──►  core/
```

`core/` imports nothing from the feature modules, and **nothing imports `cli.py`**. The
CLI keeps its feature-module imports *inside* each handler so that `enma --help`,
`enma analyze` and `enma report` never pay to import `frida` or `UnityPy`.

---

## Lint and format

```bash
uv run ruff check src/ tests/
uv run ruff check src/ tests/ --fix
uv run ruff format src/ tests/
```

## Tests

The suite is fully offline — no device, no frida-server, no network. Autouse fixtures
in `tests/conftest.py` enforce that rather than assuming it: external tool lookups
return `None`, `urlopen` raises, and `Path.home()` is redirected to a tmp dir.

```bash
uv run pytest
```

## pre-commit

```bash
uv run pre-commit install          # install hooks (once)
uv run pre-commit run --all-files  # run manually
```

## Docs

Docs dependencies live in their own group, so `uv sync` alone does not install them:

```bash
uv sync --group docs
uv run mkdocs serve                # live preview on http://127.0.0.1:8000
uv run mkdocs build --strict       # render to site/
```

---

## Adding a new agent

1. Create `src/enma/agents/{category}/{name}_agent.js`.
2. Add **one row** to `_AGENTS` in [`core/agents.py`](https://github.com/ykus4/enma/blob/main/src/enma/core/agents.py),
   tagging it with `TAG_DUMP` (included in a bare `enma dump`), `TAG_UE4`, and/or `TAG_MEM`:

    ```python
    _a("mynewagent", "network", TAG_DUMP),
    ```

3. Add an analyzer `_analyze_{name}` to `analyze.py` and register it in `_ANALYZERS`.
4. Add a renderer `_render_{name}` to `report.py` and register it in `_RENDERERS`.

`tests/test_agents.py` asserts the registry and the `agents/` tree agree in **both**
directions, so a `.js` file without a row — or a row without a `.js` file — fails CI
rather than surfacing as a runtime error.

### Agent message protocol

JavaScript → Python, over the Frida message bus:

```javascript
send({ event: "log",  message: "something happened" });
send({ event: "file", name: "output.bin" }, arrayBuffer);
send({ event: "json", name: "result.json", data: { key: "value" } });
```

The `memscan` and `mempatch` agents instead expose `rpc.exports` and are driven
synchronously from Python — see [Architecture](architecture.md).
