# Agent Reference

## Dump agents

### `dex` — DEX extraction

Three-stage strategy:
1. `InMemoryDexClassLoader` hook — captures bytes before runtime patching
2. `libart OpenMemory` hook — intercepts at the ART level
3. Memory scan — searches for `dex\n035` / `dex\n039` magic

Output: `classes_N_*.dex`, `dex_obfuscation_report.json`

### `il2cpp` — IL2CPP symbol dump

1. Dumps raw `libil2cpp.so` ELF
2. Extracts `global-metadata.dat` via `/proc/self/maps`
3. Builds an Il2CppDumper-compatible `il2cpp_dump.json` by walking `il2cpp_domain_get_assemblies`

### `assets` — Unity AssetBundle dump

1. `LoadFromMemory` hook (IL2CPP managed)
2. `libc open / mmap` hook — tracks `.unity3d` / `.bundle` file descriptors
3. Memory scan for `UnityFS` / `UnityRaw` / `UnityWeb` magic
4. APK `AssetManager.list()` enumeration

### `mono` — Mono DLL dump

1. `mono_assembly_foreach` enumeration
2. `mono_assembly_load` / `mono_image_open` hooks for late-loaded DLLs
3. MZ/PE header scan fallback

### `heap` — Java heap scan

| What | File |
|---|---|
| `SecretKeySpec`, `PrivateKey` | `heap_keys.json` |
| High-entropy `byte[]` (entropy ≥ 7.2) | `heap_bytes.json` |
| `SharedPreferences` key-value pairs | `heap_prefs.json` |
| OkHttp3 `Request` / `Response` | `heap_http.json` |
| `android.net.Uri` | `heap_uris.json` |
| Strings matching credential keywords | `heap_strings.json` |

---

## Analysis agents

### `coverage` — Code coverage (Stalker)

Uses Frida Stalker to record every unique basic block executed.
Skips system libraries. Flushes after 30 s.

Output: `coverage.json` — `{blocks: [{module, rva, size}], summary: {module: count}}`

### `tracer` — Function call tracer

Hooks all exports matching a regex pattern (default: `.*`).
Records timestamp, thread ID, call depth, arguments (hex), and return value.

Output: `trace.json` (up to 5,000 records)

### `jni` — JNI method map

Hooks `RegisterNatives` (or JNI vtable slot 215 as fallback).
Parses JNI type descriptors into human-readable signatures.

Output: `jni_map.json` — `{javaClass, javaMethod, returnType, params, module, rva}`

---

## Bypass agents

### `ssl` — SSL pinning bypass

| Target | Technique |
|---|---|
| `X509TrustManager` | Registers a permissive TrustManager |
| OkHttp3 `CertificatePinner` | Replaces `check()` with a no-op |
| TrustKit | Nullifies `PinningTrustManager.checkServerTrusted` |
| BoringSSL / libssl | `SSL_CTX_set_verify` → `VERIFY_NONE` |
| Xamarin | Clears `ServicePointManager.ServerCertificateValidationCallback` |

Also logs TLS SNI hostnames → `tls_connections.json`

### `crypto` — Key harvesting

Java: `SecretKeySpec`, `Cipher.init`, `KeyGenerator`, `KeyPairGenerator`, `MessageDigest`
Native: `AES_set_*_key`, `EVP_*Init_ex`, `d2i_RSAPrivateKey`
Memory: 32-byte sliding window, Shannon entropy ≥ 7.4

Output: `crypto_keys.json`, `rsa_private_key.der`

### `anti_detect` — Root / emulator / debugger bypass

- `java.io.File.exists()` spoofing for su / Magisk paths
- `SystemProperties.get()` — returns safe build fingerprint values
- `/proc/self/status` `TracerPid` patching
- `Debug.isDebuggerConnected()` → `false`
- `Build.TAGS` / `FINGERPRINT` / `MODEL` field spoofing

### `anti_tamper` — Integrity check bypass

- Logs `PackageInfo.GET_SIGNATURES` calls
- Patches `ptrace(PTRACE_TRACEME)` → 0
- Scrubs Frida tokens from `/proc/maps` reads
- Logs CRC32 / ZipFile self-checks

Output: `anti_tamper_log.json`

### `safetynet` — SafetyNet / Play Integrity bypass

- Logs `SafetyNetClient.attest()` and JWS result tokens
- Logs `IntegrityManager` calls
- Logs `KeyStore.getCertificateChain` (attestation chain)
- Patches `LicenseChecker.checkAccess` → always allow

Output: `safetynet_log.json`

---

## Network agents

### `http` — HTTP full-body capture

- OkHttp3: injects a `NetworkInterceptor` that peeks request/response bodies
- `HttpURLConnection`: logs URL, method, status
- Volley: hooks `parseNetworkResponse`

Output: `http_traffic.json`

### `websocket` — WebSocket monitor

- OkHttp3: wraps `WebSocketListener` and `RealWebSocket.send`
- `javax.websocket` (Tyrus): hooks `sendText`

Output: `websocket_log.json` — direction `SEND` / `RECV` / `OPEN` / `CLOSE`

### `protobuf` — Protobuf auto-decoder

Hooks protobuf-java (`MessageLite.toByteArray`, `AbstractParser.parseFrom`),
Wire (`ProtoAdapter`), and OkHttp `ResponseBody` for `application/x-protobuf`.
Includes a minimal schema-less field decoder (varint, length-delimited, 32/64-bit).

Output: `protobuf_log.json`

### `binder` — Binder / IPC monitor

- Java: `startActivity`, `sendBroadcast`, `startService` (Intent inspection)
- ContentProvider: `ContentResolver.query`, `insert`
- Native `libbinder`: `IBinder::transact` (transaction code logging)

Output: `binder_log.json`

---

## Storage agents

### `sqlite` — SQLite monitor

Hooks `SQLiteDatabase.execSQL`, `rawQuery`, `insert`, `update`, `delete`,
`SQLiteStatement`, and Jetpack Room `SupportSQLiteDatabase`.

Output: `sqlite_log.json`

### `fileio` — File I/O monitor

Java: `FileOutputStream` / `FileInputStream`, `SharedPreferences.commit`,
`java.nio.file.Files.write`
Native: `libc open` / `write` / `unlink` for paths under `/data/data/`, `/sdcard/`, etc.

Output: `fileio_log.json`

### `dlopen` — Dynamic library monitor

Hooks `dlopen`, `android_dlopen_ext`, `dlsym`, `System.loadLibrary`.
Immediately dumps newly loaded `.so` ELF binaries.

Output: `dlopen_log.json`, `dlsym_log.json`, `dlopen_*.so` binaries

---

## Unreal Engine agents

Also reachable through the dedicated [`ue4` subcommand](subcommands.md), which adds
the `--gnames` / `--gobjects` / `--process-event` address overrides and `--extract-pak`.

### `ue4_sdk` — SDK dump

Walks `GNames` / `FNamePool` and `GUObjectArray` to reconstruct the class, function,
enum and struct tables. Supports UE4.23–4.27 layouts. Pass `--gnames` / `--gobjects`
when auto-detection fails.

Output: `ue4_sdk.json`

### `ue4_pak` — PAK discovery

Hooks `FPakFile` construction and file I/O to locate `.pak` archives on the device.
With `--extract-pak`, enma then runs [u4pak](https://pypi.org/project/u4pak/) on any
archive reachable from the host.

Output: `ue4_pak_list.json`, `ue4_pak_*.pak`

### `ue4_blueprint` — Blueprint tracer

Hooks `UObject::ProcessEvent` and records Blueprint call names. Use `--process-event`
to supply the address when the symbol is stripped. The trace is flushed on Ctrl+C.

Output: `ue4_blueprint_trace.json`

---

## Memory agents

These two are RPC-driven rather than message-bus based: they are **not** part of a bare
`enma dump` and are instead driven interactively by
[`memscan` and `mempatch`](subcommands.md).

### `memscan` — Value scanner

CheatEngine-style scan → filter → results loop over every readable memory region.
Supports `int8`–`int64`, `uint8`–`uint64`, `float`, `double` and `bytes`.

### `mempatch` — Memory writer

Writes a typed value, raw bytes, or architecture-appropriate NOP sleds to an address,
with an optional freeze loop that rewrites the value on an interval.

---

