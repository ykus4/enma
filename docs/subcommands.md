# Subcommands

## `setup` — Deploy frida-server

```bash
uv run enma setup
uv run enma setup -s R3CN30XXXXX   # specify device serial
uv run enma setup --force          # force re-push
```

Detects device ABI, downloads the matching `frida-server` from GitHub releases,
pushes it to `/data/local/tmp/frida-server`, and starts it via `su`.
Downloaded binaries are cached in `~/.cache/enma/`.

---

## `list` — Enumerate apps

```bash
uv run enma list
uv run enma list -s <serial>
```

```
  com.example.game           My Game  [PID 12345]
  com.example.another        Another App
```

---

## `dump` — Run agents

```bash
uv run enma dump <target> [options]
```

| Option | Description |
|---|---|
| `-t TYPE [TYPE …]` | Run specific agents only (default: all) |
| `-o DIR` | Output directory (default: `./dump`) |
| `-s SERIAL` | ADB device serial |
| `--spawn` | Spawn the app instead of attaching |
| `--watch` | Wait for the process to start, then attach |
| `--retry` | Re-attach automatically when the process dies |
| `--timeout N` | Auto-detach after N seconds |

```bash
# All agents
uv run enma dump com.example.game

# Selected agents
uv run enma dump com.example.game -t dex il2cpp jni crypto

# Bypass agents only (stealth mode)
uv run enma dump com.example.game -t ssl anti_detect anti_tamper safetynet

# Spawn + custom output + timeout
uv run enma dump com.example.game --spawn -o ./out --timeout 60
```

**Available agent types:**

| Category | Agents |
|---|---|
| Dump | `dex` `il2cpp` `assets` `mono` `heap` |
| Analysis | `coverage` `tracer` `jni` |
| Bypass | `ssl` `crypto` `anti_detect` `anti_tamper` `safetynet` |
| Network | `http` `websocket` `protobuf` `binder` |
| Storage | `sqlite` `fileio` `dlopen` |

---

## `analyze` — Post-dump analysis

```bash
uv run enma analyze <dump_dir>
uv run enma analyze ./dump -o custom_report.json
```

Reads all artifact files in the dump directory, runs optional external tools, and writes `report.json`.

What it covers:
- DEX obfuscation ratio + jadx decompilation
- IL2CPP method/field counts + security-relevant method flagging
- JNI mappings by native module
- Crypto key and heap key candidate summary
- Native `.so` URL / JWT string extraction
- TLS, HTTP, WebSocket, SQLite, Binder, File I/O, Protobuf summaries
- dlopen load log, code coverage, anti-tamper bypass log

---

## `report` — HTML report

```bash
uv run enma report <dump_dir>
uv run enma report ./dump --json custom.json -o out.html
```

Converts `report.json` into a self-contained dark-theme HTML report with:
- Summary stat cards
- Collapsible sections per category
- Color-coded severity badges (high / med / low / info)

---

## `repack` — frida-gadget injection (no root)

```bash
uv run enma repack app.apk
uv run enma repack app.apk -o app-gadget.apk --arch arm64
```

| Option | Description |
|---|---|
| `-o PATH` | Output APK path |
| `--arch` | `arm64` (default) / `arm` / `x86_64` / `x86` |
| `--keep-workdir` | Keep the intermediate smali directory |

Requires on `PATH`: `apktool`, `zipalign`, and `apksigner` (Android build-tools) or `jarsigner` (JDK).

Pipeline:
1. Download `frida-gadget-{ver}-android-{arch}.so.xz` → cached in `~/.cache/enma/`
2. `apktool d` — decode APK
3. Copy gadget `.so` to `lib/{arch}/`
4. Inject a smali `Application` subclass that calls `System.loadLibrary("frida-gadget")`
5. `apktool b` → zipalign → sign with debug keystore

After installing the repacked APK, frida-gadget listens on port 27042 and acts as a standard frida-server.

---

## `unity` — Extract AssetBundles

```bash
uv run enma unity <dump_dir>
uv run enma unity ./dump -o ./extracted
```

Requires the `enma[unity]` extra (see [Installation](index.md#installation)).

Extracts from every `.unity3d` bundle in the dump directory:

| Asset type | Output |
|---|---|
| `Texture2D` | PNG |
| `AudioClip` | WAV / OGG |
| `TextAsset` | `.txt` / `.bytes` |
| `Sprite` | PNG |
| `MonoBehaviour` | JSON (via typetree) |

---

## `memscan` — Memory value scanner

Interactive CheatEngine-style REPL for locating values in process memory.

```bash
uv run enma memscan com.example.game
uv run enma memscan com.example.game --spawn
```

```
memscan> scan 9999 int32          # first scan — find all addresses = 9999
[*] Scan #1: 48,302 results

# change the value in-game (e.g. spend coins, take damage)

memscan> filter 9990 eq           # narrow to addresses now = 9990
[*] Scan #2: 3 results remaining

memscan> results
  0x7ff1a2b4  =  9990
  0x7ff3c100  =  9990
  0x7ff3c104  =  9990

memscan> read 0x7ff1a2b4 int32    # confirm the value
  0x7ff1a2b4  =  9990
```

**Commands:**

| Command | Description |
|---|---|
| `scan <value> [type]` | First scan — search all readable memory |
| `filter <value> [op]` | Narrow results by comparison operator |
| `results [max]` | Show current result list |
| `read <addr> <type>` | Read a single value |
| `reset` | Clear all results and start over |
| `info` | Show scan state (type, scan count, result count) |
| `help` | Show command reference |
| `quit` / `exit` | Detach and exit |

**Supported types:** `int8` `int16` `int32` `int64` `uint8` `uint16` `uint32` `uint64` `float` `double` `bytes`

**Filter operators:** `eq` `ne` `gt` `lt` `gte` `lte` `changed` `unchanged`

---

## `mempatch` — Memory write / freeze

```bash
uv run enma mempatch com.example.game <addr> [options]
```

| Option | Description |
|---|---|
| `-t TYPE` | Value type (default: `int32`) |
| `-v VALUE` | Value to write |
| `--nop N` | Write N NOP instructions (arch-aware: arm64 / arm / x86) |
| `--bytes HEX …` | Write raw bytes, e.g. `--bytes DE AD BE EF` |
| `--freeze` | Continuously overwrite the value (Ctrl+C to stop) |
| `--interval MS` | Freeze interval in ms (default: 100) |

!!! note "`-v` on `mempatch`"
    Every other subcommand accepts `-v` as a shorthand for `--verbose`. On `mempatch`,
    `-v` is `--value`, so debug logging is available only as the long `--verbose`.
    Because both now exist here, the abbreviation `--v` has become ambiguous — write
    `-v` / `--value` or `--verbose` in full.

```bash
# Write a value once
uv run enma mempatch com.example.game 0x7ff1a2b4 -t int32 -v 99999

# Freeze a float value (e.g. player speed)
uv run enma mempatch com.example.game 0x7ff3c100 -t float -v 9999.0 --freeze

# NOP out 4 instructions (e.g. disable a check)
uv run enma mempatch com.example.game 0x7ff00100 --nop 4

# Raw byte patch
uv run enma mempatch com.example.game 0x7ff00200 --bytes 00 00 A0 E3
```

> **Tip**: use `memscan` to locate the address first, then `mempatch` to write to it.

---

