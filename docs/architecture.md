# enma — Architecture

This document describes the system architecture, data flow, and component relationships of enma.

---

## System Overview

enma is a two-process system: a **Python host** running on the analyst's machine and **JavaScript agents** injected into the target Android process via Frida.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Analyst Machine                                                    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  enma CLI  (Python)                                         │   │
│  │                                                             │   │
│  │  cli.py ──► dump.py         (agent orchestration)          │   │
│  │         ──► frida_server.py (frida-server deploy)          │   │
│  │         ──► repack.py       (APK gadget injection)         │   │
│  │         ──► mem.py          (memscan / mempatch REPL)      │   │
│  │         ──► analyze.py      (post-dump analysis)           │   │
│  │         ──► report.py       (HTML report generation)       │   │
│  │         ──► unity.py        (AssetBundle extraction)       │   │
│  │         ──► ue4.py          (UE4 runtime analysis)         │   │
│  │                    │                                        │   │
│  │                    └──► core/  (agents, session, abi,      │   │
│  │                                 download)                   │   │
│  └────────────────────────┬────────────────────────────────────┘   │
│                           │ Frida RPC / message bus                │
│                           │ (USB / TCP)                            │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────────┐
│  Android Device           │                                         │
│                           ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  frida-server  (or frida-gadget in repacked APK)            │   │
│  └────────────────────────┬────────────────────────────────────┘   │
│                           │ ptrace / /proc injection               │
│                           ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Target App Process                                         │   │
│  │                                                             │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │   │
│  │  │ Java VM  │  │ ART / JIT│  │ Native   │  │ libc /   │   │   │
│  │  │ (Dalvik) │  │ (libart) │  │ Libs     │  │ BoringSSL│   │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │   │
│  │       │             │             │              │           │   │
│  │       └─────────────┴─────────────┴──────────────┘           │   │
│  │                           ▲                                   │   │
│  │                    Frida Interceptors                         │   │
│  │                    (JS agents injected)                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Agent Categories

The 25 agents are grouped into 7 functional categories, each in its own subdirectory.
The 23 non-`mem` agents make up the default set for a bare `enma dump`; the two `mem`
agents are RPC-driven and are reached through `memscan` / `mempatch` instead.

```
agents/
│
├── dump/          ← Extract binary artifacts from memory
│   ├── dex_agent.js        DEX bytecode (3 strategies)
│   ├── il2cpp_agent.js     libil2cpp.so + metadata + symbol map
│   ├── assets_agent.js     Unity AssetBundles (4 strategies)
│   ├── mono_agent.js       Mono managed DLLs
│   └── heap_agent.js       Java heap scan (keys, strings, prefs)
│
├── analysis/      ← Observe execution behaviour
│   ├── coverage_agent.js   Basic-block coverage (Frida Stalker)
│   ├── tracer_agent.js     Function call trace (args + retval)
│   └── jni_agent.js        JNI RegisterNatives map
│
├── bypass/        ← Neutralize detection and verification
│   ├── ssl_agent.js        SSL pinning bypass (5 methods)
│   ├── crypto_agent.js     Crypto key harvesting
│   ├── anti_detect_agent.js  Root/emulator/debugger detection bypass
│   ├── anti_tamper_agent.js  Signature/CRC/ptrace bypass
│   └── safetynet_agent.js    SafetyNet / Play Integrity bypass
│
├── network/       ← Intercept inter-process & network communication
│   ├── http_agent.js       OkHttp3 / HttpURLConnection full-body capture
│   ├── websocket_agent.js  WebSocket frame logging
│   ├── protobuf_agent.js   Schema-less Protobuf decoding
│   └── binder_agent.js     Android Binder IPC monitoring
│
├── storage/       ← Track persistent storage access
│   ├── sqlite_agent.js     SQLite query/mutation logging
│   ├── fileio_agent.js     File open/write/delete monitoring
│   └── dlopen_agent.js     Dynamic library load monitoring
│
├── ue4/           ← Unreal Engine 4 runtime analysis
│   ├── ue4_sdk_agent.js    GNames/GUObjectArray dump → SDK JSON (UE4.23–4.27)
│   ├── ue4_pak_agent.js    PAK file discovery and dump
│   └── ue4_blueprint_agent.js  Blueprint ProcessEvent call tracer
│
└── mem/           ← Interactive memory manipulation
    ├── memscan_agent.js    CheatEngine-style value scanner
    └── mempatch_agent.js   Write / NOP / freeze memory
```

---

## Data Flow

### Dump workflow

```
enma dump com.example.game
        │
        ├─ get_device()          detect / select ADB device
        ├─ attach_or_spawn()     attach to or spawn target PID
        └─ load_scripts()        inject all requested agents
               │
               │  [per agent]
               ├─ script.load()  inject JS into target process
               │
               │  target process runtime
               │  ┌─────────────────────────────────────┐
               │  │  hook fires (e.g. AES_set_*_key)    │
               │  │  collect data into in-memory buffer  │
               │  │  periodic flush or on-demand send    │
               │  └─────────────────┬───────────────────┘
               │                    │ send(payload, data)
               │                    ▼
               │  on_message() handler (Python)
               │  ┌──────────────────────────────┐
               │  │  event: "log"   → print       │
               │  │  event: "file"  → write bytes  │
               │  │  event: "json"  → write JSON   │
               │  └──────────────────────────────┘
               │                    │
               └────────────────────▼
                         dump/  (output directory)
```

### Analysis and report workflow

```
dump/                     (raw artifact files)
  │
  ▼
enma analyze ./dump
  │
  ├─ _analyze_dex()       ──► jadx decompilation
  ├─ _analyze_il2cpp()    ──► Il2CppDumper (optional)
  ├─ _analyze_jni()       ──► parse jni_map.json
  ├─ _analyze_crypto()    ──► parse crypto_keys.json
  ├─ _analyze_tls()       ──► parse tls_connections.json
  ├─ _analyze_http()      ──► parse http_traffic.json
  ├─ _analyze_*()         ──► (17 analyzers total)
  │
  └─► report.json
          │
          ▼
  enma report ./dump
          │
          └─► report.html  (self-contained, dark theme)
```

### memscan / mempatch workflow

```
enma memscan com.example.game
        │
        ├─ attach to process
        ├─ inject memscan_agent.js
        │
        │  analyst REPL loop
        │  ┌──────────────────────────────────────────────┐
        │  │  memscan> scan 9999 int32                     │
        │  │       rpc.scan("9999", "int32")               │
        │  │         ──► JS scans all readable regions     │
        │  │         ◄── {count: 48302, scanCount: 1}      │
        │  │                                               │
        │  │  [change value in-game]                       │
        │  │                                               │
        │  │  memscan> filter 9990 eq                      │
        │  │       rpc.filter("9990", "eq")                │
        │  │         ──► JS re-reads each saved address    │
        │  │         ◄── {count: 3, scanCount: 2}          │
        │  │                                               │
        │  │  memscan> results                             │
        │  │         ◄── [{addr, value}, …]               │
        │  └──────────────────────────────────────────────┘
        │
enma mempatch com.example.game 0x7ff1a2b4 -t int32 -v 99999
        │
        ├─ attach to process
        ├─ inject mempatch_agent.js
        ├─ rpc.write("0x7ff1a2b4", "int32", 99999)
        │    ──► Memory.protect(ptr, 4, "rw-")
        │    ──► ptr.writeS32(99999)
        └─ detach
```

---

## Component Interaction Map

Dependencies flow one way — `cli.py` ──► feature modules ──► `core/`. Nothing
imports `cli.py`, and `core/` imports no feature module.

```
┌──────────────────────────────────────────────────────────────────┐
│  cli.py            (argument parser + dispatch only)             │
│                                                                  │
│  _build_parser()   eager:  core.agents, core.abi  (frida-free)  │
│  _DISPATCH         lazy :  one feature module per handler        │
│    "dump"     ──► run_dump()    ◄── dump.py                     │
│    "list"     ──► list_apps()   ◄── dump.py                     │
│    "memscan"  ──► run_memscan() ◄── mem.py                      │
│    "mempatch" ──► run_mempatch()◄── mem.py                      │
│    "analyze"  ──► run_analyze() ◄── analyze.py                  │
│    "report"   ──► run_report()  ◄── report.py                   │
│    "unity"    ──► run_unity()   ◄── unity.py                    │
│    "setup"    ──► run_setup()   ◄── frida_server.py             │
│    "repack"   ──► run_repack()  ◄── repack.py                   │
│    "ue4"      ──► run_ue4()     ◄── ue4.py                      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  core/agents.py   (single source of truth — 25 agents)          │
│                                                                  │
│  _AGENTS = (Agent(name, category, tags), …)                     │
│      │        tags: TAG_DUMP / TAG_UE4 / TAG_MEM                │
│      ├─► DUMP_AGENTS (23)  → `dump` default set, -t choices     │
│      ├─► UE4_AGENTS  (3)   → `ue4` -t choices                   │
│      ├─► MEM_AGENTS  (2)   → memscan / mempatch                 │
│      ├─► load_agent(name)  → agents/{category}/{name}_agent.js  │
│      └─► discover()        → the tree, for the drift test       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  core/session.py  (frida device + session lifecycle)             │
│                                                                  │
│  connect(args)            get_device + attach / spawn / watch    │
│  load_scripts()           inject agents, wire make_on_message    │
│  run_until_detached()     block; returns True if interrupted     │
│       ▲              ▲              ▲                            │
│  dump.py          ue4.py         mem.py                          │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  core/download.py                    core/abi.py                 │
│                                                                  │
│  cache_dir()        ~/.cache/enma/   abi_to_arch()  arm64-v8a →  │
│  download_github_asset()             arch_to_abi()      arm64    │
│       ▲              ▲                    ▲          ▲           │
│  frida_server.py   repack.py       frida_server.py  repack.py    │
│  (server .xz)      (gadget .so.xz)                   cli.py      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  analyze.py                                                      │
│                                                                  │
│  _load_json(path)     ← shared JSON loader (None if absent)     │
│  _count_by(data, key) ← shared tally helper                     │
│                                                                  │
│  _ANALYZERS = [                                                  │
│    _analyze_dex, _analyze_il2cpp, _analyze_jni,                 │
│    _analyze_crypto, _analyze_assets, _analyze_mono,             │
│    _analyze_native_strings, _analyze_tls, _analyze_http,        │
│    _analyze_sqlite, _analyze_binder, _analyze_coverage,         │
│    _analyze_dlopen, _analyze_protobuf, _analyze_anti_tamper,    │
│    _analyze_safetynet, _analyze_fileio,                         │
│  ]                           │                                   │
│                              ▼ report.json                       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  report.py                                                       │
│                                                                  │
│  _RENDERERS = {                                                  │
│    "dex":          _render_dex,                                  │
│    "il2cpp":       _render_il2cpp,                               │
│    "jni":          _render_jni,                                  │
│    "crypto":       _render_crypto,                               │
│    "tls":          _render_tls,                                  │
│    "native_strings": _render_native_strings,                    │
│    "assets":       _render_assets,                               │
│    "http":         _render_http,                                 │
│    "sqlite":       _render_sqlite,                               │
│    "binder":       _render_binder,                               │
│    "coverage":     _render_coverage,                             │
│    "dlopen":       _render_dlopen,                               │
│    "protobuf":     _render_protobuf,                             │
│    "anti_tamper":  _render_anti_tamper,                          │
│    "safetynet":    _render_safetynet,                            │
│    "fileio":       _render_fileio,                               │
│    "mono":         _render_mono,                                 │
│  }                           │                                   │
│                              ▼ report.html                       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Agent Message Protocol

All agents communicate with the Python host using a three-event protocol over the Frida message bus.

```
JavaScript side                        Python side (on_message)
──────────────────────────────────     ──────────────────────────────────

// Progress / status
send({ event: "log",
       message: "Scanning heap..." })  → print("[agent] Scanning heap...")

// Binary file dump
send({ event: "file",
       name: "libil2cpp.so" },
     arrayBuffer)                      → Path(out_dir/libil2cpp.so)
                                           .write_bytes(data)

// Structured data
send({ event: "json",
       name: "crypto_keys.json",
       data: [{algorithm: "AES", ...}] }) → json.dump(data, open(...))
```

For `memscan` and `mempatch`, agents expose RPC functions instead of using the message bus:

```
Python                                 JavaScript (rpc.exports)
──────────────────────────────         ──────────────────────────────
script.exports_sync.scan(              rpc.exports = {
  "9999", "int32")                       scan(value, type) { … },
                                         filter(value, filterType) { … },
script.exports_sync.write(              write(addr, type, value) { … },
  "0x7ff1a2b4", "int32", 99999)          nop(addr, count) { … },
                                         freeze(addr, type, value) { … },
                                       }
```

---

## Hook Layers

Each agent operates at one or more of the following hook layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4: Java / Kotlin API                                     │
│  Java.use("javax.crypto.spec.SecretKeySpec")                    │
│  Java.use("okhttp3.OkHttpClient$Builder")                       │
│  Java.use("android.app.ActivityManager")                        │
│  → crypto, ssl, http, binder, heap, sqlite, fileio, …          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: ART / Dalvik internals                                │
│  Interceptor.attach(Module.findExportByName("libart.so", …))    │
│  → dex (OpenMemory), jni (RegisterNatives)                      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Native libraries                                      │
│  Interceptor.attach(Module.findExportByName("libssl.so", …))    │
│  Interceptor.attach(Module.findExportByName("libcrypto.so", …)) │
│  Interceptor.attach(Module.findExportByName("libUE4.so", …))    │
│  → ssl (BoringSSL), crypto (EVP_*), dlopen (libdl),             │
│    ue4_sdk (GNames/GUObjectArray), ue4_pak (FPakFile),           │
│    ue4_blueprint (ProcessEvent)                                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: libc / syscall                                        │
│  Interceptor.attach(Module.findExportByName("libc.so", "open")) │
│  → fileio, assets (mmap), mono                                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 0: Frida Stalker (code instrumentation)                  │
│  Stalker.follow(threadId, { events: { block: true }, … })       │
│  → coverage                                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Deployment Modes

### Rooted device (default)

```
Analyst ──USB──► ADB ──► frida-server ──ptrace──► Target app
                         /data/local/tmp/
```

`enma setup` automates the frida-server deployment.

### No-root: frida-gadget injection

```
app.apk ──► enma repack ──► app-gadget.apk
                                        │
                                   install + launch
                                        │
                              frida-gadget.so loads
                              (via smali Application.onCreate)
                                        │
                              listens on tcp:27042
                                        │
Analyst ──ADB port-forward──► frida connect
```

### Emulator

Works identically to rooted device mode. Connect via `adb connect localhost:5555` (or the emulator's ADB serial).
