# enma

A [Frida](https://frida.re)-based Android security research toolkit for extracting and analyzing runtime artifacts — DEX files, IL2CPP binaries, Unity assets, crypto keys, network traffic, and more.

!!! warning "Intended use"
    Penetration testing, CTF challenges, security research, and reverse engineering of apps you own or have explicit permission to analyze.

---

## Requirements

| Dependency | Notes |
|---|---|
| Python 3.12+ | |
| [uv](https://docs.astral.sh/uv/) | Package manager |
| [ADB](https://developer.android.com/tools/adb) | In `PATH` |
| Rooted device **or** emulator | AVD / Genymotion |
| frida-server | Auto-deployed by `enma setup` |

Optional, for [`analyze`](subcommands.md):

| Tool | Purpose |
|---|---|
| [jadx](https://github.com/skylot/jadx) | DEX / Mono DLL decompilation |
| [apktool](https://apktool.org) | APK decoding |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | IL2CPP symbol extraction |
| `strings` | Native `.so` string extraction |

Analysis degrades gracefully when these are missing — each step is skipped with a warning rather than failing the run.

---

## Installation

```bash
git clone https://github.com/ykus4/enma
cd enma
uv sync
```

Activate the virtual environment (optional — prefix commands with `uv run` instead):

```bash
source .venv/bin/activate
```

For Unity asset extraction, install the optional extra:

```bash
uv pip install "enma[unity]"
```

---

## Quick Start

```bash
# 1. Push frida-server to device
uv run enma setup

# 2. Find the target package name
uv run enma list

# 3. Dump all artifacts
uv run enma dump com.example.game -o ./dump

# 4. Run post-dump analysis
uv run enma analyze ./dump

# 5. Open the HTML report
uv run enma report ./dump
open ./dump/report.html
```

---

## Where to go next

| Page | Contents |
|---|---|
| [Subcommands](subcommands.md) | Every CLI command, with flags and examples |
| [Agent Reference](agents.md) | What each of the 25 JS agents hooks and emits |
| [Output Files](output-files.md) | What lands in the dump directory |
| [Architecture](architecture.md) | System design, data flow, hook layers |
| [Development](development.md) | Project layout, tests, adding an agent |

---

## Disclaimer

Use only against apps you own or have explicit written authorization to analyze.
Dumped files may contain sensitive cryptographic material — handle with care.
