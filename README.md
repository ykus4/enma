# enma

A [Frida](https://frida.re)-based Android security research toolkit for extracting and analyzing runtime artifacts — DEX files, IL2CPP binaries, Unity assets, crypto keys, network traffic, and more.

> **Intended use**: penetration testing, CTF challenges, security research, and reverse engineering of apps you own or have explicit permission to analyze.

**📖 Full documentation: <https://ykus4.github.io/enma>**

---

## Install

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/), ADB in `PATH`, and a rooted device or emulator.

```bash
git clone https://github.com/ykus4/enma
cd enma
uv sync
```

## Quick start

```bash
uv run enma setup                            # push frida-server to the device
uv run enma list                             # find the target package
uv run enma dump com.example.game -o ./dump  # run the agents
uv run enma analyze ./dump                   # post-dump analysis
uv run enma report ./dump                    # → dump/report.html
```

## Documentation

| Page | Contents |
|---|---|
| [Subcommands](https://ykus4.github.io/enma/subcommands/) | Every CLI command, with flags and examples |
| [Agent Reference](https://ykus4.github.io/enma/agents/) | What each of the 25 JS agents hooks and emits |
| [Output Files](https://ykus4.github.io/enma/output-files/) | What lands in the dump directory |
| [Architecture](https://ykus4.github.io/enma/architecture/) | System design, data flow, hook layers |
| [Development](https://ykus4.github.io/enma/development/) | Project layout, tests, adding an agent |

Docs live in [`docs/`](docs/) and are built with MkDocs:

```bash
uv sync --group docs
uv run mkdocs serve
```

## Development

```bash
uv run ruff check src/ tests/
uv run pytest
```

See the [Development guide](https://ykus4.github.io/enma/development/) for the project layout and how to add an agent.

---

## Disclaimer

Use only against apps you own or have explicit written authorization to analyze.
Dumped files may contain sensitive cryptographic material — handle with care.

Licensed under the [MIT License](LICENSE).
