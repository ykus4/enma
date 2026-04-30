"use strict";
/**
 * File I/O Monitor Agent
 *
 * Monitors all file reads/writes to /data/data/<pkg>/ and other sensitive paths.
 * Captures:
 *   - Java FileOutputStream / FileInputStream writes and reads
 *   - SharedPreferences backing file writes (XML commits)
 *   - Native libc open / read / write / unlink
 *
 * Output: fileio_log.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const fileLog = [];
const MAX     = 3000;

const INTERESTING = [
    "/data/data/",
    "/data/user/",
    "/sdcard/",
    "/storage/emulated/",
    "shared_prefs",
    "databases",
    "files",
    "cache",
];

function isInteresting(path) {
    if (!path) return false;
    return INTERESTING.some(p => path.includes(p));
}

function record(op, path, size) {
    if (fileLog.length >= MAX) return;
    fileLog.push({ ts: Date.now(), op, path, size: size ?? null });
    log(`[fileio] ${op}: ${path}${size != null ? `  (${size}B)` : ""}`);
}

// ── 1. Java FileOutputStream / FileInputStream ────────────────────────────────

function hookJavaFileIO() {
    Java.perform(() => {
        // FileOutputStream.$init
        try {
            const FOS = Java.use("java.io.FileOutputStream");
            FOS.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
                const path = file.getAbsolutePath().toString();
                if (isInteresting(path)) record("open_write", path, null);
                return this.$init(file, append);
            };
        } catch (_) {}

        // FileOutputStream.write(byte[], int, int)
        try {
            const FOS = Java.use("java.io.FileOutputStream");
            FOS.write.overload("[B", "int", "int").implementation = function (buf, off, len) {
                // Path is not directly accessible here; rely on open hook above
                this.write(buf, off, len);
            };
        } catch (_) {}

        // FileInputStream.$init
        try {
            const FIS = Java.use("java.io.FileInputStream");
            FIS.$init.overload("java.io.File").implementation = function (file) {
                const path = file.getAbsolutePath().toString();
                if (isInteresting(path)) record("open_read", path, null);
                return this.$init(file);
            };
        } catch (_) {}

        // SharedPreferences XML commit
        try {
            const SPE = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            if (SPE.commit) {
                SPE.commit.implementation = function () {
                    record("shared_prefs_commit", "SharedPreferences", null);
                    return this.commit();
                };
            }
            if (SPE.apply) {
                SPE.apply.implementation = function () {
                    record("shared_prefs_apply", "SharedPreferences", null);
                    return this.apply();
                };
            }
        } catch (_) {}

        // java.nio.file.Files (API 26+)
        try {
            const Files = Java.use("java.nio.file.Files");
            Files.write.overload(
                "java.nio.file.Path", "[B", "[Ljava.nio.file.OpenOption;"
            ).implementation = function (path, bytes, opts) {
                record("Files.write", path.toString(), bytes.length);
                return this.write(path, bytes, opts);
            };
        } catch (_) {}
    });
}

// ── 2. Native libc open / write / unlink ─────────────────────────────────────

function hookNativeFileIO() {
    const openPtr   = Module.findExportByName("libc.so", "open");
    const writePtr  = Module.findExportByName("libc.so", "write");
    const unlinkPtr = Module.findExportByName("libc.so", "unlink");

    const openFds = new Map(); // fd -> path

    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter(args) { try { this._path = args[0].readUtf8String(); } catch (_) {} },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd >= 0 && isInteresting(this._path)) {
                    openFds.set(fd, this._path);
                    record("native_open", this._path, null);
                }
            },
        });
    }

    if (writePtr) {
        Interceptor.attach(writePtr, {
            onEnter(args) {
                this._fd  = args[0].toInt32();
                this._len = args[2].toInt32();
            },
            onLeave() {
                const path = openFds.get(this._fd);
                if (path) record("native_write", path, this._len);
            },
        });
    }

    if (unlinkPtr) {
        Interceptor.attach(unlinkPtr, {
            onEnter(args) {
                try {
                    const path = args[0].readUtf8String();
                    if (isInteresting(path)) record("native_unlink", path, null);
                } catch (_) {}
            },
        });
    }
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (fileLog.length > 0) sendJson("fileio_log.json", fileLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[fileio] Agent loaded");
hookNativeFileIO();
Java.performNow(hookJavaFileIO);

setInterval(flush, 10000);
setTimeout(flush, 60000);
