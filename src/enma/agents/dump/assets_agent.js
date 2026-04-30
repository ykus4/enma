"use strict";
/**
 * Unity AssetBundle Dump Agent
 *
 * Strategies:
 *   1. Hook UnityEngine's AssetBundle.LoadFromMemory / LoadFromFile* family
 *      via the managed C# bridge (il2cpp or mono).
 *   2. Hook native libc open/read to detect .unity3d / .bundle paths and
 *      capture file descriptors as they are read into memory.
 *   3. Scan /proc/self/maps for anonymous rwx regions that contain the
 *      UnityFS or UnityRaw magic bytes and dump them.
 */

const UNITY_FS_MAGIC  = "55 6e 69 74 79 46 53"; // "UnityFS"
const UNITY_RAW_MAGIC = "55 6e 69 74 79 52 61 77"; // "UnityRaw"
const UNITY_WEB_MAGIC = "55 6e 69 74 79 57 65 62"; // "UnityWeb"

let dumpCounter = 0;
const dumpedKeys = new Set();

function log(msg) {
    send({ event: "log", message: msg });
}

function sendFile(name, buf) {
    send({ event: "file", name: name }, buf);
}

function saveRegion(base, size, label) {
    const key = base.toString();
    if (dumpedKeys.has(key)) return;
    dumpedKeys.add(key);

    if (size <= 0 || size > 512 * 1024 * 1024) {
        log(`[assets] Skipping ${label}: suspicious size ${size}`);
        return;
    }
    try {
        const buf  = base.readByteArray(size);
        const name = `asset_${++dumpCounter}_${label}.unity3d`;
        log(`[assets] Saving ${name}  size=${size}  addr=${base}`);
        sendFile(name, buf);
    } catch (e) {
        log(`[assets] Read failed at ${base} (${label}): ${e}`);
    }
}

// ── Strategy 1: IL2CPP managed hooks ─────────────────────────────────────────

function hookManagedLoadFunctions() {
    // Find exports dynamically — names vary by Unity version
    const il2cpp = Process.findModuleByName("libil2cpp.so")
        || Process.findModuleByName("libunity.so");
    if (!il2cpp) {
        log("[assets] libil2cpp.so / libunity.so not found");
        return;
    }

    // Enumerate exports that contain "AssetBundle" and "LoadFromMemory"
    il2cpp.enumerateExports().forEach(exp => {
        if (exp.name.includes("AssetBundle") && exp.name.includes("LoadFromMemory")) {
            log(`[assets] Hooking managed: ${exp.name}`);
            try {
                Interceptor.attach(exp.address, {
                    onEnter(args) {
                        // arg conventions differ by Unity version; arg1 is typically
                        // Il2CppArray* (byte[]) for LoadFromMemory(byte[], uint crc)
                        this.arrayPtr = args[1];
                    },
                    onLeave(retval) {
                        if (!this.arrayPtr || this.arrayPtr.isNull()) return;
                        try {
                            // Il2CppArray: 16-byte header, then data
                            const dataPtr = this.arrayPtr.add(16);
                            // Read array length from header offset 12
                            const len = this.arrayPtr.add(12).readU32();
                            if (len > 0 && len < 256 * 1024 * 1024) {
                                saveRegion(dataPtr, len, "managed_loadmem");
                            }
                        } catch (e) {
                            log(`[assets] managed hook read error: ${e}`);
                        }
                    },
                });
            } catch (e) {
                log(`[assets] Hook failed for ${exp.name}: ${e}`);
            }
        }
    });
}

// ── Strategy 2: libc open hook ────────────────────────────────────────────────

const openedAssetFds = new Map(); // fd -> path

function hookLibcOpen() {
    const openPtr = Module.findExportByName("libc.so", "open");
    if (!openPtr) { log("[assets] libc open not found"); return; }

    Interceptor.attach(openPtr, {
        onEnter(args) {
            try {
                this.path = args[0].readUtf8String();
            } catch (_) {
                this.path = null;
            }
        },
        onLeave(retval) {
            if (!this.path) return;
            const p = this.path.toLowerCase();
            if (
                p.endsWith(".unity3d") ||
                p.endsWith(".bundle")  ||
                p.endsWith(".assetbundle") ||
                p.includes("streamingassets")
            ) {
                const fd = retval.toInt32();
                if (fd >= 0) {
                    openedAssetFds.set(fd, this.path);
                    log(`[assets] open() intercepted: fd=${fd}  path=${this.path}`);
                }
            }
        },
    });

    // Hook mmap to capture entire file mappings for asset fds
    const mmapPtr = Module.findExportByName("libc.so", "mmap64")
        || Module.findExportByName("libc.so", "mmap");
    if (!mmapPtr) return;

    Interceptor.attach(mmapPtr, {
        onEnter(args) {
            this.length = args[1].toInt32();
            this.fd     = args[4].toInt32();
        },
        onLeave(retval) {
            if (retval.isNull()) return;
            if (!openedAssetFds.has(this.fd)) return;
            const path  = openedAssetFds.get(this.fd);
            const label = path.split("/").pop().replace(/[^a-zA-Z0-9._-]/g, "_");
            log(`[assets] mmap for ${path}  size=${this.length}`);
            saveRegion(retval, this.length, label);
        },
    });

    log("[assets] libc open/mmap hooks installed");
}

// ── Strategy 3: Memory scan for UnityFS / UnityRaw / UnityWeb ────────────────

function scanMemoryForAssets() {
    log("[assets] Scanning memory for UnityFS/UnityRaw/UnityWeb magic...");
    let found = 0;

    const patterns = [
        { magic: UNITY_FS_MAGIC,  label: "UnityFS"  },
        { magic: UNITY_RAW_MAGIC, label: "UnityRaw" },
        { magic: UNITY_WEB_MAGIC, label: "UnityWeb" },
    ];

    Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-")).forEach(range => {
        if (range.size < 64) return;
        for (const { magic, label } of patterns) {
            try {
                Memory.scanSync(range.base, range.size, magic, {
                    onMatch(address) {
                        // Read the file size from the bundle header.
                        // UnityFS header: magic(7), \n(1), version(4 BE), unityVer(str), engineVer(str), bundleSize(8 BE)
                        // Quick approach: just dump up to end of region from match point
                        const remaining = range.size - address.sub(range.base).toInt32();
                        // Attempt to parse bundle size (offset 0x12 in FS header, 8-byte BE)
                        let size = remaining;
                        if (label === "UnityFS") {
                            try {
                                // Skip to bundleSize field: magic(7)+\n(1)+ver(4) = 12 bytes,
                                // then two null-terminated strings (version strings, typically short)
                                // Use a safe cap instead of full parse
                                size = Math.min(remaining, 64 * 1024 * 1024);
                            } catch (_) {}
                        }
                        saveRegion(address, size, label);
                        found++;
                    },
                    onError() {},
                    onComplete() {},
                });
            } catch (_) {}
        }
    });

    log(`[assets] Memory scan complete. Found ${found} asset region(s).`);
}

// ── Strategy 4: Enumerate app's assets directory via Java ────────────────────

function dumpAssetsDirectory() {
    Java.perform(() => {
        try {
            const context = Java.use("android.app.ActivityThread")
                .currentApplication()
                .getApplicationContext();
            const assetManager = context.getAssets();

            function listDir(path) {
                let entries;
                try {
                    entries = assetManager.list(path);
                } catch (_) { return; }
                for (let i = 0; i < entries.length; i++) {
                    const entry    = entries[i].toString();
                    const fullPath = path ? path + "/" + entry : entry;
                    // Recurse into sub-directories
                    const sub = assetManager.list(fullPath);
                    if (sub && sub.length > 0) {
                        listDir(fullPath);
                    } else if (
                        entry.endsWith(".unity3d") ||
                        entry.endsWith(".bundle")  ||
                        entry.endsWith(".assetbundle")
                    ) {
                        log(`[assets] Reading APK asset: ${fullPath}`);
                        try {
                            const stream = assetManager.open(fullPath);
                            const JByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                            const out = JByteArrayOutputStream.$new();
                            const JByteArray = Java.array("byte", new Array(65536).fill(0));
                            let n;
                            while ((n = stream.read(JByteArray)) !== -1) {
                                out.write(JByteArray, 0, n);
                            }
                            stream.close();
                            const jbytes = out.toByteArray();
                            const len    = jbytes.length;
                            const ab     = new ArrayBuffer(len);
                            new Uint8Array(ab).set(jbytes.map(b => b & 0xff));
                            const name   = fullPath.replace(/\//g, "_");
                            log(`[assets] Saving APK asset: ${name}  size=${len}`);
                            sendFile(name, ab);
                        } catch (e) {
                            log(`[assets] Could not read ${fullPath}: ${e}`);
                        }
                    }
                }
            }

            listDir("");
        } catch (e) {
            log(`[assets] APK asset enumeration failed: ${e}`);
        }
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[assets] Agent loaded");
hookManagedLoadFunctions();
hookLibcOpen();
dumpAssetsDirectory();

// Scan after app fully loads assets
setTimeout(scanMemoryForAssets, 5000);
