"use strict";
/**
 * Binder / IPC Monitor Agent
 *
 * Intercepts Android IPC at multiple layers:
 *   1. Java ActivityManager / PackageManager / Intent dispatches
 *   2. ContentProvider queries and inserts
 *   3. Native libbinder transact() for raw Binder transactions
 *
 * Output: binder_log.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const binderLog = [];
const MAX = 2000;

function record(type, detail) {
    if (binderLog.length >= MAX) return;
    binderLog.push({ ts: Date.now(), type, ...detail });
    log(`[binder] ${type}: ${JSON.stringify(detail).slice(0, 120)}`);
}

// ── 1. Intent / Activity / Service / Broadcast ────────────────────────────────

function hookIntents() {
    Java.perform(() => {
        // startActivity
        try {
            const AT = Java.use("android.app.Activity");
            AT.startActivity.overload("android.content.Intent").implementation = function (intent) {
                try {
                    record("startActivity", {
                        action:    intent.getAction()?.toString() ?? null,
                        component: intent.getComponent()?.toString() ?? null,
                        data:      intent.getDataString()?.toString() ?? null,
                    });
                } catch (_) {}
                return this.startActivity(intent);
            };
        } catch (_) {}

        // sendBroadcast
        try {
            const CTX = Java.use("android.content.ContextWrapper");
            CTX.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
                try {
                    record("sendBroadcast", { action: intent.getAction()?.toString() ?? null });
                } catch (_) {}
                return this.sendBroadcast(intent);
            };
        } catch (_) {}

        // startService
        try {
            const CTX2 = Java.use("android.content.ContextWrapper");
            CTX2.startService.overload("android.content.Intent").implementation = function (intent) {
                try {
                    record("startService", {
                        component: intent.getComponent()?.toString() ?? null,
                        action:    intent.getAction()?.toString() ?? null,
                    });
                } catch (_) {}
                return this.startService(intent);
            };
        } catch (_) {}
    });
}

// ── 2. ContentProvider ────────────────────────────────────────────────────────

function hookContentProvider() {
    Java.perform(() => {
        try {
            const CR = Java.use("android.content.ContentResolver");

            CR.query.overload(
                "android.net.Uri",
                "[Ljava.lang.String;",
                "android.os.Bundle",
                "android.os.CancellationSignal"
            ).implementation = function (uri, proj, sel, cancel) {
                record("ContentResolver.query", { uri: uri.toString() });
                return this.query(uri, proj, sel, cancel);
            };

            CR.insert.overload(
                "android.net.Uri",
                "android.content.ContentValues"
            ).implementation = function (uri, values) {
                record("ContentResolver.insert", {
                    uri:    uri.toString(),
                    keys:   values ? values.keySet().toString() : null,
                });
                return this.insert(uri, values);
            };
        } catch (_) {}
    });
}

// ── 3. Native libbinder transact() ───────────────────────────────────────────

function hookNativeBinder() {
    const libbinder = Process.findModuleByName("libbinder.so");
    if (!libbinder) { log("[binder] libbinder.so not found"); return; }

    // android::IBinder::transact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
    const sym = libbinder.enumerateExports().find(e => e.name.includes("transact") && e.name.includes("IBinder"));
    if (!sym) { log("[binder] IBinder::transact not found"); return; }

    try {
        Interceptor.attach(sym.address, {
            onEnter(args) {
                this.code = args[1].toInt32();
            },
            onLeave(retval) {
                record("IBinder.transact", { code: this.code, status: retval.toInt32() });
            },
        });
        log(`[binder] Hooked IBinder::transact`);
    } catch (e) { log(`[binder] transact hook failed: ${e}`); }
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (binderLog.length > 0) sendJson("binder_log.json", binderLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[binder] Agent loaded");
hookNativeBinder();
Java.performNow(() => {
    hookIntents();
    hookContentProvider();
});

setInterval(flush, 10000);
setTimeout(flush, 60000);
