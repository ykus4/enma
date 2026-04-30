"use strict";
/**
 * SSL Pinning Bypass Agent
 *
 * Bypasses:
 *   1. Android TrustManager (custom X509TrustManager)
 *   2. OkHttp3 CertificatePinner / OkHostnameVerifier
 *   3. TrustKit / Appmattus pinning
 *   4. Native SSL_CTX_set_verify (OpenSSL / BoringSSL)
 *   5. Xamarin / Mono ServicePointManager
 *
 * Also logs TLS SNI hostnames to tls_connections.json.
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const tlsLog = [];

// ── 1. Java TrustManager bypass ───────────────────────────────────────────────

function bypassTrustManager() {
    Java.perform(() => {
        // Register a permissive TrustManager and inject it into the default SSLContext
        try {
            const X509TM = Java.use("javax.net.ssl.X509TrustManager");
            const SSLCtx = Java.use("javax.net.ssl.SSLContext");

            const BypassTM = Java.registerClass({
                name: "com.enma.BypassTrustManager",
                implements: [X509TM],
                methods: {
                    checkClientTrusted(chain, authType) {},
                    checkServerTrusted(chain, authType) {
                        log(`[ssl] checkServerTrusted bypassed: ${authType}`);
                    },
                    getAcceptedIssuers() {
                        return Java.array("java.security.cert.X509Certificate", []);
                    },
                },
            });

            const sslCtx = SSLCtx.getInstance("TLS");
            sslCtx.init(null, Java.array("javax.net.ssl.TrustManager", [BypassTM.$new()]), null);
            SSLCtx.getDefault.implementation = function () { return sslCtx; };
            log("[ssl] TrustManager bypass installed");
        } catch (e) {
            log(`[ssl] TrustManager bypass failed: ${e}`);
        }

        // Null out checkServerTrusted on all already-loaded TrustManager implementations
        try {
            const classes = Java.enumerateLoadedClassesSync().filter(
                c => c.includes("TrustManager") || c.includes("CertPinner")
            );
            for (const cls of classes) {
                try {
                    const C = Java.use(cls);
                    if (C.checkServerTrusted) {
                        C.checkServerTrusted.overloads.forEach(ovl => {
                            ovl.implementation = function (...args) {
                                log(`[ssl] Bypassed ${cls}.checkServerTrusted`);
                            };
                        });
                    }
                } catch (_) {}
            }
        } catch (_) {}

        // Always-true HostnameVerifier (registered once)
        try {
            const HV = Java.use("javax.net.ssl.HttpsURLConnection");
            const BypassHV = Java.registerClass({
                name: "com.enma.BypassHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify(host, session) {
                        log(`[ssl] HostnameVerifier: ${host} -> true`);
                        return true;
                    },
                },
            });
            HV.setDefaultHostnameVerifier.implementation = function (v) {
                log("[ssl] setDefaultHostnameVerifier -> always-true");
                return this.setDefaultHostnameVerifier(BypassHV.$new());
            };
        } catch (_) {}
    });
}

// ── 2. OkHttp3 bypass ────────────────────────────────────────────────────────

function bypassOkHttp3() {
    Java.perform(() => {
        try {
            const CP = Java.use("okhttp3.CertificatePinner");
            CP.check.overloads.forEach(ovl => {
                ovl.implementation = function (hostname, ...rest) {
                    log(`[ssl] OkHttp3 CertificatePinner.check bypassed: ${hostname}`);
                };
            });
            log("[ssl] OkHttp3 CertificatePinner bypassed");
        } catch (_) {}

        try {
            const OHV = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
            OHV.verify.overloads.forEach(ovl => {
                ovl.implementation = function (hostname, ...rest) {
                    log(`[ssl] OkHostnameVerifier.verify: ${hostname} -> true`);
                    return true;
                };
            });
        } catch (_) {}
    });
}

// ── 3. TrustKit bypass ────────────────────────────────────────────────────────

function bypassTrustKit() {
    Java.perform(() => {
        const classes = [
            "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
            "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
        ];
        for (const cls of classes) {
            try {
                const C = Java.use(cls);
                if (C.checkServerTrusted) {
                    C.checkServerTrusted.overloads.forEach(o => {
                        o.implementation = function (...a) {
                            log(`[ssl] TrustKit ${cls} bypassed`);
                        };
                    });
                }
            } catch (_) {}
        }
    });
}

// ── 4. Native OpenSSL / BoringSSL ────────────────────────────────────────────

function bypassNativeSsl() {
    const libs = ["libssl.so", "libcronet.so", "libconscrypt_jni.so", "libcronet.86.so"];

    for (const lib of libs) {
        if (!Process.findModuleByName(lib)) continue;

        const setVerify = Module.findExportByName(lib, "SSL_CTX_set_verify");
        if (setVerify) {
            try {
                Interceptor.attach(setVerify, {
                    onEnter(args) {
                        args[1] = ptr(0);
                        args[2] = ptr(0);
                        log(`[ssl] SSL_CTX_set_verify -> VERIFY_NONE (${lib})`);
                    },
                });
            } catch (_) {}
        }

        const getResult = Module.findExportByName(lib, "SSL_get_verify_result");
        if (getResult) {
            try {
                Interceptor.replace(getResult, new NativeCallback(() => 0, "long", ["pointer"]));
                log(`[ssl] SSL_get_verify_result -> 0 (${lib})`);
            } catch (_) {}
        }

        const getSNI = Module.findExportByName(lib, "SSL_get_servername");
        if (getSNI) {
            try {
                Interceptor.attach(getSNI, {
                    onLeave(retval) {
                        if (!retval.isNull()) {
                            const host = retval.readUtf8String();
                            if (host) {
                                log(`[ssl] TLS SNI: ${host}`);
                                tlsLog.push({ ts: Date.now(), sni: host });
                            }
                        }
                    },
                });
            } catch (_) {}
        }
    }
}

// ── 5. Xamarin / Mono ServicePointManager ────────────────────────────────────

function bypassXamarin() {
    // Only attempt if a Mono runtime is present; Java.use on Mono classes
    // is only valid inside a Mono-enabled app (Xamarin).
    if (!["libmono.so", "libmono-2.0.so"].some(n => !!Process.findModuleByName(n))) return;

    Java.perform(() => {
        try {
            const SPM = Java.use("System.Net.ServicePointManager");
            SPM.ServerCertificateValidationCallback.value = null;
            log("[ssl] Xamarin ServicePointManager: callback cleared");
        } catch (_) {}
    });
}

// ── Flush TLS log ─────────────────────────────────────────────────────────────

function flushTlsLog() {
    if (tlsLog.length > 0) sendJson("tls_connections.json", tlsLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[ssl] Agent loaded — installing SSL pinning bypasses");
bypassNativeSsl();

Java.performNow(() => {
    bypassTrustManager();
    bypassOkHttp3();
    bypassTrustKit();
    bypassXamarin();
});

setInterval(flushTlsLog, 10000);
