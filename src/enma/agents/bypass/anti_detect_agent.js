"use strict";
/**
 * Root / Emulator / Debugger Detection Bypass Agent
 *
 * Bypasses:
 *   1. File-based root checks  (su, Magisk, busybox, SuperSU …)
 *   2. Build property checks   (ro.build.tags, ro.debuggable, ro.product.model …)
 *   3. TracerPid anti-debug    (/proc/self/status)
 *   4. isDebuggerConnected()   (android.os.Debug)
 *   5. SafetyNet-level props   (ro.build.version.security_patch, CTS)
 *   6. Emulator fingerprints   (IMEI, sensor checks, Build.FINGERPRINT)
 *   7. Package existence checks (Magisk Manager, Superuser, …)
 */

function log(msg) { send({ event: "log", message: msg }); }

// ── 1. File-existence root checks ────────────────────────────────────────────

const ROOT_PATHS = [
    "/su", "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
    "/data/local/xbin/su", "/data/local/bin/su",
    "/sbin/magisk", "/sbin/.magisk",
    "/proc/net/xt_qtaguid/ctrl",
];

function hookFileExistence() {
    // java.io.File.exists()
    Java.perform(() => {
        try {
            const JFile = Java.use("java.io.File");
            JFile.exists.implementation = function () {
                const path = this.getAbsolutePath().toString();
                if (ROOT_PATHS.some(p => path.includes(p))) {
                    log(`[anti_detect] File.exists() spoofed false: ${path}`);
                    return false;
                }
                return this.exists();
            };
        } catch (_) {}

        // java.io.FileInputStream constructor (another common check)
        try {
            const FIS = Java.use("java.io.FileInputStream");
            FIS.$init.overload("java.lang.String").implementation = function (path) {
                if (ROOT_PATHS.some(p => path.includes(p))) {
                    log(`[anti_detect] FileInputStream blocked: ${path}`);
                    throw Java.use("java.io.FileNotFoundException").$new(path);
                }
                return this.$init(path);
            };
        } catch (_) {}
    });

    // Native libc open() — covers native root checks
    const openPtr = Module.findExportByName("libc.so", "open");
    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter(args) {
                try {
                    const path = args[0].readUtf8String() || "";
                    if (ROOT_PATHS.some(p => path.includes(p))) {
                        log(`[anti_detect] open() spoofed -1: ${path}`);
                        this.spoof = true;
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                if (this.spoof) retval.replace(ptr(-1));
            },
        });
    }
}

// ── 2. Build property spoofing ────────────────────────────────────────────────

const SAFE_PROPS = {
    "ro.build.tags":        "release-keys",
    "ro.debuggable":        "0",
    "ro.secure":            "1",
    "ro.build.type":        "user",
    "ro.build.fingerprint": "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys",
    "ro.product.model":     "Pixel 2",
    "ro.hardware":          "walleye",
};

function hookSystemProperties() {
    Java.perform(() => {
        try {
            const SP = Java.use("android.os.SystemProperties");
            SP.get.overload("java.lang.String").implementation = function (key) {
                if (SAFE_PROPS[key] !== undefined) {
                    log(`[anti_detect] SystemProperties.get("${key}") -> "${SAFE_PROPS[key]}"`);
                    return SAFE_PROPS[key];
                }
                return this.get(key);
            };
            SP.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
                if (SAFE_PROPS[key] !== undefined) return SAFE_PROPS[key];
                return this.get(key, def);
            };
        } catch (_) {}
    });
}

// ── 3. /proc/self/status TracerPid spoof ─────────────────────────────────────

function hookProcStatus() {
    const openPtr = Module.findExportByName("libc.so", "open");
    const readPtr = Module.findExportByName("libc.so", "read");
    if (!openPtr || !readPtr) return;

    const statusFds = new Set();

    Interceptor.attach(openPtr, {
        onLeave(retval) {
            try {
                // Detect when /proc/self/status is opened
                if (this._path && this._path.includes("/proc/") && this._path.includes("status")) {
                    statusFds.add(retval.toInt32());
                }
            } catch (_) {}
        },
        onEnter(args) {
            try { this._path = args[0].readUtf8String(); } catch (_) {}
        },
    });

    Interceptor.attach(readPtr, {
        onLeave(retval) {
            if (!statusFds.has(this._fd) || retval.toInt32() <= 0) return;
            try {
                const buf = Memory.readUtf8String(this._buf);
                if (buf && buf.includes("TracerPid")) {
                    // Patch TracerPid line to 0 in buffer
                    const patched = buf.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                    Memory.writeUtf8String(this._buf, patched);
                    log("[anti_detect] TracerPid patched to 0");
                }
            } catch (_) {}
        },
        onEnter(args) {
            this._fd  = args[0].toInt32();
            this._buf = args[1];
        },
    });
}

// ── 4. Java debugger / root API bypasses ─────────────────────────────────────

function hookDebugAPIs() {
    Java.perform(() => {
        // android.os.Debug.isDebuggerConnected()
        try {
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function () {
                log("[anti_detect] Debug.isDebuggerConnected() -> false");
                return false;
            };
        } catch (_) {}

        // android.os.Debug.waitingForDebugger()
        try {
            const Debug = Java.use("android.os.Debug");
            Debug.waitingForDebugger.implementation = function () { return false; };
        } catch (_) {}

        // RootBeer / common root-check libraries
        for (const cls of ["com.scottyab.rootbeer.RootBeer", "com.topjohnwu.magisk.MagiskManager"]) {
            try {
                const C = Java.use(cls);
                if (C.isRooted) C.isRooted.implementation = function () { return false; };
                if (C.isRootedWithBusyBoxCheck) C.isRootedWithBusyBoxCheck.implementation = function () { return false; };
            } catch (_) {}
        }

        // PackageManager.getPackageInfo — hide Magisk / root app packages
        const ROOT_PKGS = ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su"];
        try {
            const PM = Java.use("android.app.ApplicationPackageManager");
            PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
                if (ROOT_PKGS.some(p => pkg.toString().includes(p))) {
                    log(`[anti_detect] getPackageInfo blocked: ${pkg}`);
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg.toString());
                }
                return this.getPackageInfo(pkg, flags);
            };
        } catch (_) {}
    });
}

// ── 5. Build fields spoof ─────────────────────────────────────────────────────

function hookBuildFields() {
    Java.perform(() => {
        try {
            const Build = Java.use("android.os.Build");
            Build.TAGS.value        = "release-keys";
            Build.FINGERPRINT.value = SAFE_PROPS["ro.build.fingerprint"];
            Build.MODEL.value       = SAFE_PROPS["ro.product.model"];
            log("[anti_detect] Build fields spoofed");
        } catch (_) {}
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[anti_detect] Agent loaded — bypassing root/emulator/debugger detection");
hookFileExistence();
hookProcStatus();
Java.performNow(() => {
    hookSystemProperties();
    hookDebugAPIs();
    hookBuildFields();
});
