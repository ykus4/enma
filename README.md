# enma

A [Frida](https://frida.re)-based Android security research toolkit for extracting and analyzing runtime artifacts — DEX files, IL2CPP binaries, Unity assets, crypto keys, network traffic, and more.

> **Intended use**: penetration testing, CTF challenges, security research, and reverse engineering of apps you own or have explicit permission to analyze.

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Subcommands](#subcommands)
  - [setup](#setup--deploy-frida-server)
  - [list](#list--enumerate-apps)
  - [dump](#dump--run-agents)
  - [analyze](#analyze--post-dump-analysis)
  - [report](#report--html-report)
  - [repack](#repack--frida-gadget-injection-no-root)
  - [unity](#unity--extract-assetbundles)
  - [memscan](#memscan--memory-value-scanner)
  - [mempatch](#mempatch--memory-write--freeze)
- [Agent Reference](#agent-reference)
- [Output Files](#output-files)
- [Project Layout](#project-layout)
- [Development](#development)

---

## Requirements

| Dependency | Notes |
|---|---|
| Python 3.12+ | |
| [uv](https://docs.astral.sh/uv/) | Package manager |
| [ADB](https://developer.android.com/tools/adb) | In `PATH` |
| Rooted device **or** emulator | AVD / Genymotion |
| frida-server | Auto-deployed by `enma setup` |

Optional (for `analyze`):

| Tool | Purpose |
|---|---|
| [jadx](https://github.com/skylot/jadx) | DEX / Mono DLL decompilation |
| [apktool](https://apktool.org) | APK decoding |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | IL2CPP symbol extraction |
| `strings` | Native `.so` string extraction |

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

## Subcommands

### `setup` — Deploy frida-server

```bash
uv run enma setup
uv run enma setup -s R3CN30XXXXX   # specify device serial
uv run enma setup --force          # force re-push
```

Detects device ABI, downloads the matching `frida-server` from GitHub releases,
pushes it to `/data/local/tmp/frida-server`, and starts it via `su`.
Downloaded binaries are cached in `~/.cache/enma/`.

---

### `list` — Enumerate apps

```bash
uv run enma list
uv run enma list -s <serial>
```

```
  com.example.game           My Game  [PID 12345]
  com.example.another        Another App
```

---

### `dump` — Run agents

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

### `analyze` — Post-dump analysis

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

### `report` — HTML report

```bash
uv run enma report <dump_dir>
uv run enma report ./dump --json custom.json -o out.html
```

Converts `report.json` into a self-contained dark-theme HTML report with:
- Summary stat cards
- Collapsible sections per category
- Color-coded severity badges (high / med / low / info)

---

### `repack` — frida-gadget injection (no root)

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

### `unity` — Extract AssetBundles

```bash
uv run enma unity <dump_dir>
uv run enma unity ./dump -o ./extracted
```

Requires the `enma[unity]` extra (see [Installation](#installation)).

Extracts from every `.unity3d` bundle in the dump directory:

| Asset type | Output |
|---|---|
| `Texture2D` | PNG |
| `AudioClip` | WAV / OGG |
| `TextAsset` | `.txt` / `.bytes` |
| `Sprite` | PNG |
| `MonoBehaviour` | JSON (via typetree) |

---

### `memscan` — Memory value scanner

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

### `mempatch` — Memory write / freeze

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

## Agent Reference

### Dump agents

#### `dex` — DEX extraction

Three-stage strategy:
1. `InMemoryDexClassLoader` hook — captures bytes before runtime patching
2. `libart OpenMemory` hook — intercepts at the ART level
3. Memory scan — searches for `dex\n035` / `dex\n039` magic

Output: `classes_N_*.dex`, `dex_obfuscation_report.json`

#### `il2cpp` — IL2CPP symbol dump

1. Dumps raw `libil2cpp.so` ELF
2. Extracts `global-metadata.dat` via `/proc/self/maps`
3. Builds an Il2CppDumper-compatible `il2cpp_dump.json` by walking `il2cpp_domain_get_assemblies`

#### `assets` — Unity AssetBundle dump

1. `LoadFromMemory` hook (IL2CPP managed)
2. `libc open / mmap` hook — tracks `.unity3d` / `.bundle` file descriptors
3. Memory scan for `UnityFS` / `UnityRaw` / `UnityWeb` magic
4. APK `AssetManager.list()` enumeration

#### `mono` — Mono DLL dump

1. `mono_assembly_foreach` enumeration
2. `mono_assembly_load` / `mono_image_open` hooks for late-loaded DLLs
3. MZ/PE header scan fallback

#### `heap` — Java heap scan

| What | File |
|---|---|
| `SecretKeySpec`, `PrivateKey` | `heap_keys.json` |
| High-entropy `byte[]` (entropy ≥ 7.2) | `heap_bytes.json` |
| `SharedPreferences` key-value pairs | `heap_prefs.json` |
| OkHttp3 `Request` / `Response` | `heap_http.json` |
| `android.net.Uri` | `heap_uris.json` |
| Strings matching credential keywords | `heap_strings.json` |

---

### Analysis agents

#### `coverage` — Code coverage (Stalker)

Uses Frida Stalker to record every unique basic block executed.
Skips system libraries. Flushes after 30 s.

Output: `coverage.json` — `{blocks: [{module, rva, size}], summary: {module: count}}`

#### `tracer` — Function call tracer

Hooks all exports matching a regex pattern (default: `.*`).
Records timestamp, thread ID, call depth, arguments (hex), and return value.

Output: `trace.json` (up to 5,000 records)

#### `jni` — JNI method map

Hooks `RegisterNatives` (or JNI vtable slot 215 as fallback).
Parses JNI type descriptors into human-readable signatures.

Output: `jni_map.json` — `{javaClass, javaMethod, returnType, params, module, rva}`

---

### Bypass agents

#### `ssl` — SSL pinning bypass

| Target | Technique |
|---|---|
| `X509TrustManager` | Registers a permissive TrustManager |
| OkHttp3 `CertificatePinner` | Replaces `check()` with a no-op |
| TrustKit | Nullifies `PinningTrustManager.checkServerTrusted` |
| BoringSSL / libssl | `SSL_CTX_set_verify` → `VERIFY_NONE` |
| Xamarin | Clears `ServicePointManager.ServerCertificateValidationCallback` |

Also logs TLS SNI hostnames → `tls_connections.json`

#### `crypto` — Key harvesting

Java: `SecretKeySpec`, `Cipher.init`, `KeyGenerator`, `KeyPairGenerator`, `MessageDigest`
Native: `AES_set_*_key`, `EVP_*Init_ex`, `d2i_RSAPrivateKey`
Memory: 32-byte sliding window, Shannon entropy ≥ 7.4

Output: `crypto_keys.json`, `rsa_private_key.der`

#### `anti_detect` — Root / emulator / debugger bypass

- `java.io.File.exists()` spoofing for su / Magisk paths
- `SystemProperties.get()` — returns safe build fingerprint values
- `/proc/self/status` `TracerPid` patching
- `Debug.isDebuggerConnected()` → `false`
- `Build.TAGS` / `FINGERPRINT` / `MODEL` field spoofing

#### `anti_tamper` — Integrity check bypass

- Logs `PackageInfo.GET_SIGNATURES` calls
- Patches `ptrace(PTRACE_TRACEME)` → 0
- Scrubs Frida tokens from `/proc/maps` reads
- Logs CRC32 / ZipFile self-checks

Output: `anti_tamper_log.json`

#### `safetynet` — SafetyNet / Play Integrity bypass

- Logs `SafetyNetClient.attest()` and JWS result tokens
- Logs `IntegrityManager` calls
- Logs `KeyStore.getCertificateChain` (attestation chain)
- Patches `LicenseChecker.checkAccess` → always allow

Output: `safetynet_log.json`

---

### Network agents

#### `http` — HTTP full-body capture

- OkHttp3: injects a `NetworkInterceptor` that peeks request/response bodies
- `HttpURLConnection`: logs URL, method, status
- Volley: hooks `parseNetworkResponse`

Output: `http_traffic.json`

#### `websocket` — WebSocket monitor

- OkHttp3: wraps `WebSocketListener` and `RealWebSocket.send`
- `javax.websocket` (Tyrus): hooks `sendText`

Output: `websocket_log.json` — direction `SEND` / `RECV` / `OPEN` / `CLOSE`

#### `protobuf` — Protobuf auto-decoder

Hooks protobuf-java (`MessageLite.toByteArray`, `AbstractParser.parseFrom`),
Wire (`ProtoAdapter`), and OkHttp `ResponseBody` for `application/x-protobuf`.
Includes a minimal schema-less field decoder (varint, length-delimited, 32/64-bit).

Output: `protobuf_log.json`

#### `binder` — Binder / IPC monitor

- Java: `startActivity`, `sendBroadcast`, `startService` (Intent inspection)
- ContentProvider: `ContentResolver.query`, `insert`
- Native `libbinder`: `IBinder::transact` (transaction code logging)

Output: `binder_log.json`

---

### Storage agents

#### `sqlite` — SQLite monitor

Hooks `SQLiteDatabase.execSQL`, `rawQuery`, `insert`, `update`, `delete`,
`SQLiteStatement`, and Jetpack Room `SupportSQLiteDatabase`.

Output: `sqlite_log.json`

#### `fileio` — File I/O monitor

Java: `FileOutputStream` / `FileInputStream`, `SharedPreferences.commit`,
`java.nio.file.Files.write`
Native: `libc open` / `write` / `unlink` for paths under `/data/data/`, `/sdcard/`, etc.

Output: `fileio_log.json`

#### `dlopen` — Dynamic library monitor

Hooks `dlopen`, `android_dlopen_ext`, `dlsym`, `System.loadLibrary`.
Immediately dumps newly loaded `.so` ELF binaries.

Output: `dlopen_log.json`, `dlsym_log.json`, `dlopen_*.so` binaries

---

## Output Files

| File | Description |
|---|---|
| `classes_N_*.dex` | Dumped DEX files |
| `dex_obfuscation_report.json` | Obfuscation ratio (ProGuard / R8 detection) |
| `libil2cpp.so` | IL2CPP native ELF |
| `global-metadata.dat` | Unity IL2CPP metadata |
| `il2cpp_dump.json` | Il2CppDumper-compatible symbol map |
| `*.dll` | Mono managed assemblies |
| `asset_N_*.unity3d` | Unity AssetBundles |
| `tls_connections.json` | TLS SNI hostnames |
| `crypto_keys.json` | Harvested cryptographic keys |
| `rsa_private_key.der` | DER-encoded RSA private key |
| `jni_map.json` | JNI native method registration map |
| `heap_keys.json` | Live `SecretKey` / `PrivateKey` from heap |
| `heap_bytes.json` | High-entropy `byte[]` from heap |
| `heap_prefs.json` | `SharedPreferences` key-value pairs |
| `heap_http.json` | OkHttp3 `Request` / `Response` objects |
| `heap_uris.json` | `android.net.Uri` objects |
| `heap_strings.json` | Credential-related `String` objects |
| `http_traffic.json` | HTTP requests and responses |
| `websocket_log.json` | WebSocket frames |
| `protobuf_log.json` | Decoded Protobuf messages |
| `binder_log.json` | Binder / IPC transactions |
| `sqlite_log.json` | SQLite operations |
| `fileio_log.json` | File I/O operations |
| `dlopen_log.json` | Dynamic library load log |
| `dlopen_*.so` | Dumped dynamically loaded libraries |
| `coverage.json` | Frida Stalker code coverage |
| `trace.json` | Function call trace |
| `anti_tamper_log.json` | Anti-tamper bypass events |
| `safetynet_log.json` | SafetyNet / Play Integrity events |
| `report.json` | Consolidated analysis report |
| `report.html` | Self-contained HTML report |

---

## Project Layout

```
enma/
├── pyproject.toml
├── docs/
│   └── architecture.md         # System architecture and data-flow diagrams
└── src/enma/
    ├── cli.py                  # CLI entry point, argument parser, agent runner
    ├── device.py               # frida-server auto-deploy
    ├── repack.py               # frida-gadget APK injection
    ├── analyze.py              # Post-dump analysis pipeline
    ├── report.py               # HTML report generation
    ├── unity.py                # Unity AssetBundle extraction
    ├── mem.py                  # Memory scanner / patcher REPL
    ├── _util.py                # Shared download / cache utilities
    ├── __init__.py
    └── agents/
        ├── dump/               # dex, il2cpp, assets, mono, heap
        ├── analysis/           # coverage, tracer, jni
        ├── bypass/             # ssl, crypto, anti_detect, anti_tamper, safetynet
        ├── network/            # http, websocket, protobuf, binder
        ├── storage/            # sqlite, fileio, dlopen
        ├── ue4/                # ue4_sdk, ue4_pak, ue4_blueprint
        └── mem/                # memscan, mempatch
```

---

## Development

### Lint and format

```bash
uv run ruff check src/
uv run ruff check src/ --fix
uv run ruff format src/
```

### pre-commit

```bash
uv run pre-commit install          # install hooks (once)
uv run pre-commit run --all-files  # run manually
```

### Adding a new agent

1. Create `src/enma/agents/{category}/{name}_agent.js`
2. Add the agent name and category to `AGENT_NAMES` and `_AGENT_DIR` in [cli.py](src/enma/cli.py)
3. Add an analyzer function `_analyze_{name}` to [analyze.py](src/enma/analyze.py)
4. Add a renderer `_render_{name}` and entry to `_RENDERERS` in [report.py](src/enma/report.py)

Agent message protocol (JavaScript → Python):

```javascript
send({ event: "log",  message: "something happened" });
send({ event: "file", name: "output.bin" }, arrayBuffer);
send({ event: "json", name: "result.json", data: { key: "value" } });
```

---

## Disclaimer

Use only against apps you own or have explicit written authorization to analyze.
Dumped files may contain sensitive cryptographic material — handle with care.
