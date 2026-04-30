"use strict";
/**
 * Dynamic Library Load Monitor Agent
 *
 * Hooks dlopen / android_dlopen_ext to:
 *   1. Log every native library loaded at runtime
 *   2. Detect and dump encrypted/packed .so files loaded from memory
 *   3. Hook dlsym to track which symbols are resolved (potential API surface)
 *
 * Output:
 *   dlopen_log.json  — all dlopen calls with path, flags, result
 *   dlopen_dumps/    — ELF binaries dumped immediately after load
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendFile(name, buf) { send({ event: "file", name: name }, buf); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const dlopenLog  = [];
const symLog     = [];
const dumpedLibs = new Set();
const MAX        = 1000;

function record(path, flags, handle) {
    if (dlopenLog.length >= MAX) return;
    const entry = { ts: Date.now(), path, flags, handle: handle ? handle.toString() : null };
    dlopenLog.push(entry);
    log(`[dlopen] dlopen: ${path}  flags=${flags}  handle=${entry.handle}`);
}

function dumpLoadedLib(handle, hint) {
    if (!handle || handle.isNull()) return;
    const key = handle.toString();
    if (dumpedLibs.has(key)) return;
    dumpedLibs.add(key);

    // Find the module that was just loaded by scanning new modules
    for (const mod of Process.enumerateModules()) {
        if (hint && !mod.path.includes(hint) && !mod.name.includes(hint)) continue;
        if (dumpedLibs.has(mod.base.toString())) continue;
        dumpedLibs.add(mod.base.toString());
        try {
            const buf = mod.base.readByteArray(mod.size);
            const safeName = mod.name.replace(/[^a-zA-Z0-9._-]/g, "_");
            sendFile(`dlopen_${safeName}`, buf);
            log(`[dlopen] Dumped: ${mod.name}  base=${mod.base}  size=${mod.size}`);
        } catch (e) { log(`[dlopen] Dump failed for ${mod.name}: ${e}`); }
    }
}

// ── Hook dlopen ───────────────────────────────────────────────────────────────

function hookDlopen() {
    const targets = [
        { lib: null, sym: "dlopen" },
        { lib: "libdl.so", sym: "dlopen" },
        { lib: "libandroid.so", sym: "android_dlopen_ext" },
    ];

    for (const { lib, sym } of targets) {
        const addr = lib ? Module.findExportByName(lib, sym) : Module.findExportByName(null, sym);
        if (!addr) continue;
        try {
            Interceptor.attach(addr, {
                onEnter(args) {
                    try { this._path = args[0].isNull() ? "<null>" : args[0].readUtf8String(); } catch (_) { this._path = "?"; }
                    this._flags = args[1].toInt32();
                },
                onLeave(retval) {
                    record(this._path, this._flags, retval);
                    if (!retval.isNull() && this._path !== "<null>") {
                        // Dump the lib after a brief delay to let loader finish mapping
                        const pathHint = this._path.split("/").pop().replace(".so", "");
                        const handle = retval;
                        setTimeout(() => dumpLoadedLib(handle, pathHint), 500);
                    }
                },
            });
            log(`[dlopen] Hooked ${sym} (${lib ?? "global"})`);
            break; // one hook is enough
        } catch (e) { log(`[dlopen] Hook failed for ${sym}: ${e}`); }
    }
}

// ── Hook dlsym ────────────────────────────────────────────────────────────────

function hookDlsym() {
    const addr = Module.findExportByName(null, "dlsym")
        || Module.findExportByName("libdl.so", "dlsym");
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            try { this._sym = args[1].readUtf8String(); } catch (_) { this._sym = "?"; }
        },
        onLeave(retval) {
            if (symLog.length < MAX && this._sym && this._sym !== "?") {
                symLog.push({ ts: Date.now(), symbol: this._sym, resolved: !retval.isNull() });
                log(`[dlopen] dlsym: ${this._sym} -> ${retval.isNull() ? "NULL" : retval}`);
            }
        },
    });
    log("[dlopen] dlsym hooked");
}

// ── Hook System.loadLibrary / System.load (Java side) ────────────────────────

function hookJavaLoad() {
    Java.perform(() => {
        try {
            const Runtime = Java.use("java.lang.Runtime");
            Runtime.loadLibrary0.overloads.forEach(ovl => {
                ovl.implementation = function (...args) {
                    log(`[dlopen] System.loadLibrary: ${args[args.length - 1]}`);
                    return ovl.apply(this, args);
                };
            });
        } catch (_) {}

        try {
            const System = Java.use("java.lang.System");
            System.load.implementation = function (path) {
                log(`[dlopen] System.load: ${path}`);
                return this.load(path);
            };
        } catch (_) {}
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (dlopenLog.length > 0) sendJson("dlopen_log.json", dlopenLog);
    if (symLog.length > 0)    sendJson("dlsym_log.json", symLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[dlopen] Agent loaded");
hookDlopen();
hookDlsym();
Java.performNow(hookJavaLoad);

setInterval(flush, 10000);
setTimeout(flush, 60000);
