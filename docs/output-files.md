# Output Files

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

