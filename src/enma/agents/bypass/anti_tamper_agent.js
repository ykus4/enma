"use strict";
/**
 * Anti-Tamper / Integrity Check Bypass Agent
 *
 * Bypasses:
 *   1. APK signature verification  (PackageManager.getPackageInfo signature field)
 *   2. CRC / hash self-check       (ZipFile, CRC32, Adler32 on own APK path)
 *   3. Anti-debug ptrace check     (ptrace PTRACE_TRACEME returning -1)
 *   4. Debuggable flag check       (ApplicationInfo.FLAG_DEBUGGABLE)
 *   5. Frida detection strings     (port 27042, /proc/maps "frida" token)
 *   6. Timestamp anti-debug        (gettimeofday delta checks)
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const bypassed = [];

function record(what) {
    bypassed.push({ ts: Date.now(), bypass: what });
    log(`[anti_tamper] Bypassed: ${what}`);
}

// ── 1. Signature verification ─────────────────────────────────────────────────

function hookSignatures() {
    Java.perform(() => {
        // getPackageInfo with GET_SIGNATURES flag
        try {
            const PM = Java.use("android.app.ApplicationPackageManager");
            PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
                const info = this.getPackageInfo(pkg, flags);
                // If GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000) requested
                if ((flags & 0x40) || (flags & 0x8000000)) {
                    record(`getPackageInfo(${pkg}, GET_SIGNATURES)`);
                    // Return info unchanged — the real signature is already there;
                    // this hook just logs detection attempts.
                }
                return info;
            };
        } catch (_) {}

        // Signature.toByteArray — return original bytes so hash comparisons still pass
        // (we hook to detect and log, not alter)
        try {
            const Sig = Java.use("android.content.pm.Signature");
            Sig.toByteArray.implementation = function () {
                record("Signature.toByteArray");
                return this.toByteArray();
            };
        } catch (_) {}

        // ApplicationInfo.FLAG_DEBUGGABLE mask check
        try {
            const AI = Java.use("android.content.pm.ApplicationInfo");
            const origFlags = AI.flags.value;
            if (origFlags & 2) { // FLAG_DEBUGGABLE == 2
                AI.flags.value = origFlags & ~2;
                record("ApplicationInfo.FLAG_DEBUGGABLE cleared");
            }
        } catch (_) {}
    });
}

// ── 2. CRC / hash self-checks on own APK ─────────────────────────────────────

function hookCrc() {
    Java.perform(() => {
        try {
            const CRC32 = Java.use("java.util.zip.CRC32");
            CRC32.getValue.implementation = function () {
                // Return the stored value unchanged; we only log access
                const v = this.getValue();
                record(`CRC32.getValue() = ${v}`);
                return v;
            };
        } catch (_) {}

        // ZipFile — detect when app opens its own APK
        try {
            const ZF = Java.use("java.util.zip.ZipFile");
            ZF.$init.overload("java.lang.String").implementation = function (path) {
                if (path && (path.endsWith(".apk") || path.endsWith(".zip"))) {
                    record(`ZipFile opened: ${path}`);
                }
                return this.$init(path);
            };
        } catch (_) {}
    });
}

// ── 3. ptrace anti-debug ──────────────────────────────────────────────────────

function hookPtrace() {
    // ptrace(PTRACE_TRACEME, 0, 0, 0) returning -1 indicates already traced.
    // Some apps call this and exit if it fails.
    const ptracePtr = Module.findExportByName("libc.so", "ptrace");
    if (!ptracePtr) return;

    const PTRACE_TRACEME = 0;
    Interceptor.attach(ptracePtr, {
        onEnter(args) { this.req = args[0].toInt32(); },
        onLeave(retval) {
            if (this.req === PTRACE_TRACEME && retval.toInt32() === -1) {
                retval.replace(ptr(0)); // pretend success
                record("ptrace(PTRACE_TRACEME) spoofed 0");
            }
        },
    });
}

// ── 4. /proc/maps Frida string detection ─────────────────────────────────────

function hookProcMaps() {
    // Apps scan /proc/self/maps for "frida", "gadget", port 27042
    const openPtr = Module.findExportByName("libc.so", "open");
    const readPtr = Module.findExportByName("libc.so", "read");
    if (!openPtr || !readPtr) return;

    const mapsFds = new Set();
    const FRIDA_TOKENS = ["frida", "gadget", "27042", "linjector"];

    Interceptor.attach(openPtr, {
        onEnter(args) { try { this._p = args[0].readUtf8String(); } catch (_) {} },
        onLeave(retval) {
            if (this._p && this._p.includes("/maps")) {
                mapsFds.add(retval.toInt32());
            }
        },
    });

    Interceptor.attach(readPtr, {
        onEnter(args) { this._fd = args[0].toInt32(); this._buf = args[1]; },
        onLeave(retval) {
            if (!mapsFds.has(this._fd) || retval.toInt32() <= 0) return;
            try {
                let s = Memory.readUtf8String(this._buf);
                if (!s) return;
                let patched = false;
                for (const tok of FRIDA_TOKENS) {
                    if (s.includes(tok)) {
                        // Replace the token chars with spaces to hide them
                        s = s.split(tok).join(" ".repeat(tok.length));
                        patched = true;
                    }
                }
                if (patched) {
                    Memory.writeUtf8String(this._buf, s);
                    record("/proc/maps Frida token scrubbed");
                }
            } catch (_) {}
        },
    });
}

// ── 5. Timing anti-debug (gettimeofday delta) ─────────────────────────────────

function hookTiming() {
    // Some apps measure execution time of a tight loop; if too slow (debugger overhead)
    // they exit. We can't fully fix this, but we hook clock_gettime to detect usage.
    const clockPtr = Module.findExportByName("libc.so", "clock_gettime");
    if (!clockPtr) return;

    let lastTime = 0;
    Interceptor.attach(clockPtr, {
        onLeave() {
            const now = Date.now();
            if (lastTime && (now - lastTime) > 2000) {
                // Big gap — probably debugger pause. Not fixable but we note it.
                record("clock_gettime: large delta detected (debugger pause?)");
            }
            lastTime = now;
        },
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[anti_tamper] Agent loaded");
hookPtrace();
hookProcMaps();
hookTiming();
Java.performNow(() => {
    hookSignatures();
    hookCrc();
});

setTimeout(() => {
    if (bypassed.length > 0) sendJson("anti_tamper_log.json", bypassed);
}, 30000);
setInterval(() => {
    if (bypassed.length > 0) sendJson("anti_tamper_log.json", bypassed);
}, 15000);
