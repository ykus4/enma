"use strict";
/**
 * SafetyNet / Play Integrity Bypass Agent
 *
 * Bypasses / intercepts:
 *   1. SafetyNet Attestation API  (com.google.android.gms.safetynet)
 *   2. Play Integrity API          (com.google.android.play.core.integrity)
 *   3. Key Attestation             (KeyStore hardware-backed attestation)
 *   4. Google Play license check   (com.google.android.vending.licensing)
 *
 * For research only — logs all attestation requests and responses.
 * Output: safetynet_log.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const snLog = [];

function record(type, detail) {
    snLog.push({ ts: Date.now(), type, ...detail });
    log(`[safetynet] ${type}: ${JSON.stringify(detail).slice(0, 200)}`);
}

// ── 1. SafetyNet Attestation ──────────────────────────────────────────────────

function hookSafetyNet() {
    Java.perform(() => {
        // SafetyNetClient.attest(byte[] nonce, String apiKey)
        for (const cls of [
            "com.google.android.gms.safetynet.SafetyNetClient",
            "com.google.android.gms.safetynet.SafetyNet",
        ]) {
            try {
                const C = Java.use(cls);
                if (C.attest) {
                    C.attest.overloads.forEach(ovl => {
                        ovl.implementation = function (...args) {
                            record("SafetyNet.attest", { apiKey: args[1]?.toString() ?? "?" });
                            return ovl.apply(this, args);
                        };
                    });
                }
            } catch (_) {}
        }

        // SafetyNetApi.AttestationResult — hook getJwsResult to log the JWT
        try {
            const AR = Java.use("com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse");
            if (AR.getJwsResult) {
                AR.getJwsResult.implementation = function () {
                    const jwt = this.getJwsResult().toString();
                    record("SafetyNet.JwsResult", { jwt: jwt.slice(0, 500) });
                    return this.getJwsResult();
                };
            }
        } catch (_) {}
    });
}

// ── 2. Play Integrity API ─────────────────────────────────────────────────────

function hookPlayIntegrity() {
    Java.perform(() => {
        for (const cls of [
            "com.google.android.play.core.integrity.IntegrityManager",
            "com.google.android.play.core.integrity.IntegrityTokenRequest",
        ]) {
            try {
                const C = Java.use(cls);
                // Log any method call
                for (const method of Object.getOwnPropertyNames(C)) {
                    try {
                        if (C[method] && C[method].overloads) {
                            C[method].overloads.forEach(ovl => {
                                ovl.implementation = function (...args) {
                                    record(`PlayIntegrity.${method}`, {});
                                    return ovl.apply(this, args);
                                };
                            });
                        }
                    } catch (_) {}
                }
            } catch (_) {}
        }
    });
}

// ── 3. Key Attestation (KeyStore) ─────────────────────────────────────────────

function hookKeyAttestation() {
    Java.perform(() => {
        try {
            const KKP = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
            KKP.setAttestationChallenge.implementation = function (challenge) {
                const hex = Array.from(challenge).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
                record("KeyAttestation.setAttestationChallenge", { challengeHex: hex });
                return this.setAttestationChallenge(challenge);
            };
        } catch (_) {}

        // Certificate chain from KeyStore — intercept getCertificateChain
        try {
            const KS = Java.use("java.security.KeyStore");
            KS.getCertificateChain.implementation = function (alias) {
                const chain = this.getCertificateChain(alias);
                record("KeyStore.getCertificateChain", { alias: alias.toString(), chainLen: chain ? chain.length : 0 });
                return chain;
            };
        } catch (_) {}
    });
}

// ── 4. License check bypass ───────────────────────────────────────────────────

function hookLicensing() {
    Java.perform(() => {
        for (const cls of [
            "com.google.android.vending.licensing.LicenseChecker",
            "com.google.android.vending.licensing.ServerManagedPolicy",
        ]) {
            try {
                const C = Java.use(cls);
                if (C.checkAccess) {
                    C.checkAccess.implementation = function (...args) {
                        record("LicenseCheck.checkAccess — bypassed", {});
                        // Call the callback with LICENSED (0x100)
                        try {
                            const cb = args[0];
                            cb.allow(0x100);
                        } catch (_) {}
                    };
                }
            } catch (_) {}
        }
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (snLog.length > 0) sendJson("safetynet_log.json", snLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[safetynet] Agent loaded");
Java.performNow(() => {
    hookSafetyNet();
    hookPlayIntegrity();
    hookKeyAttestation();
    hookLicensing();
});

setInterval(flush, 10000);
setTimeout(flush, 60000);
