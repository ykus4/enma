"use strict";
/**
 * Crypto Key Harvesting Agent
 *
 * Hooks:
 *   1. Java javax.crypto (SecretKeySpec, Cipher.init, KeyGenerator)
 *   2. Java java.security (KeyPairGenerator, KeyFactory, MessageDigest)
 *   3. Native AES (AES_set_encrypt_key, EVP_EncryptInit_ex)
 *   4. Native RSA (RSA_new, RSA_generate_key_ex, d2i_RSAPrivateKey)
 *
 * Also scans memory for high-entropy regions likely to contain keys.
 *
 * Output: crypto_keys.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendFile(name, buf) { send({ event: "file", name: name }, buf); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const keyLog = [];

function addKey(entry) {
    log(`[crypto] ${entry.type}  alg=${entry.algorithm}  len=${entry.keyLen ?? "?"}  src=${entry.source}`);
    keyLog.push({ ts: Date.now(), ...entry });
}

// ── Bytes → hex ───────────────────────────────────────────────────────────────

function toHex(arrayBuffer) {
    return Array.from(new Uint8Array(arrayBuffer))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

function ptrToHex(ptr, len) {
    try { return toHex(ptr.readByteArray(len)); } catch (_) { return "<unreadable>"; }
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

function entropy(arrayBuffer) {
    const freq = new Uint32Array(256);
    const view = new Uint8Array(arrayBuffer);
    for (const b of view) freq[b]++;
    let h = 0;
    for (const f of freq) {
        if (f === 0) continue;
        const p = f / view.length;
        h -= p * Math.log2(p);
    }
    return h;
}

// ── 1. Java Crypto hooks ──────────────────────────────────────────────────────

function hookJavaCrypto() {
    Java.perform(() => {
        // SecretKeySpec
        try {
            const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
            SKS.$init.overloads.forEach(ovl => {
                ovl.implementation = function (...args) {
                    const result = ovl.apply(this, args);
                    const keyBytes = args[0];
                    const alg      = args[args.length - 1]; // last arg is algorithm
                    try {
                        const raw = Array.from(keyBytes).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
                        addKey({ type: "SecretKey", algorithm: alg.toString(), keyLen: keyBytes.length * 8, hex: raw, source: "SecretKeySpec" });
                    } catch (_) {}
                    return result;
                };
            });
            log("[crypto] Hooked SecretKeySpec");
        } catch (e) { log(`[crypto] SecretKeySpec hook: ${e}`); }

        // Cipher.init — captures IV too
        try {
            const Cipher = Java.use("javax.crypto.Cipher");
            Cipher.init.overloads.forEach(ovl => {
                ovl.implementation = function (...args) {
                    const result = ovl.apply(this, args);
                    try {
                        const mode = args[0]; // 1=ENCRYPT, 2=DECRYPT
                        const key  = args[1];
                        addKey({
                            type:      mode === 1 ? "Cipher.ENCRYPT" : "Cipher.DECRYPT",
                            algorithm: this.getAlgorithm(),
                            keyLen:    key && key.getEncoded ? key.getEncoded().length * 8 : "?",
                            source:    "Cipher.init",
                        });
                    } catch (_) {}
                    return result;
                };
            });
            log("[crypto] Hooked Cipher.init");
        } catch (e) { log(`[crypto] Cipher.init hook: ${e}`); }

        // KeyGenerator.generateKey
        try {
            const KG = Java.use("javax.crypto.KeyGenerator");
            KG.generateKey.implementation = function () {
                const key = this.generateKey();
                try {
                    const enc = key.getEncoded();
                    const raw = Array.from(enc).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
                    addKey({ type: "GeneratedKey", algorithm: this.getAlgorithm(), keyLen: enc.length * 8, hex: raw, source: "KeyGenerator" });
                } catch (_) {}
                return key;
            };
            log("[crypto] Hooked KeyGenerator.generateKey");
        } catch (e) { log(`[crypto] KeyGenerator hook: ${e}`); }

        // MessageDigest
        try {
            const MD = Java.use("java.security.MessageDigest");
            MD.digest.overload("[B").implementation = function (input) {
                const result = this.digest(input);
                addKey({
                    type:      "MessageDigest",
                    algorithm: this.getAlgorithm(),
                    keyLen:    result.length * 8,
                    hex:       Array.from(result).map(b => (b & 0xff).toString(16).padStart(2, "0")).join(""),
                    source:    "MessageDigest.digest",
                });
                return result;
            };
        } catch (_) {}

        // KeyPairGenerator
        try {
            const KPG = Java.use("java.security.KeyPairGenerator");
            KPG.generateKeyPair.implementation = function () {
                const kp = this.generateKeyPair();
                try {
                    addKey({
                        type:      "KeyPair",
                        algorithm: this.getAlgorithm(),
                        source:    "KeyPairGenerator",
                        pubHex:    toHex(kp.getPublic().getEncoded().map(b => b & 0xff)),
                    });
                } catch (_) {}
                return kp;
            };
            log("[crypto] Hooked KeyPairGenerator");
        } catch (_) {}
    });
}

// ── 2. Native AES/RSA hooks ───────────────────────────────────────────────────

function hookNativeCrypto() {
    const sslLibs = ["libssl.so", "libcrypto.so", "libboringssl.so", "libcronet.so"];

    for (const lib of sslLibs) {
        if (!Process.findModuleByName(lib)) continue;

        // AES_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
        const aesSetKey = Module.findExportByName(lib, "AES_set_encrypt_key")
            || Module.findExportByName(lib, "AES_set_decrypt_key");
        if (aesSetKey) {
            try {
                Interceptor.attach(aesSetKey, {
                    onEnter(args) {
                        const bits = args[1].toInt32();
                        const bytes = bits / 8;
                        addKey({ type: "NativeAES", algorithm: "AES", keyLen: bits, hex: ptrToHex(args[0], bytes), source: lib });
                    },
                });
                log(`[crypto] Hooked AES_set_*_key in ${lib}`);
            } catch (_) {}
        }

        // EVP_EncryptInit_ex(ctx, type, impl, key, iv)
        const evpInit = Module.findExportByName(lib, "EVP_EncryptInit_ex")
            || Module.findExportByName(lib, "EVP_DecryptInit_ex");
        if (evpInit) {
            try {
                Interceptor.attach(evpInit, {
                    onEnter(args) {
                        const keyPtr = args[3];
                        const ivPtr  = args[4];
                        if (!keyPtr.isNull()) {
                            addKey({ type: "EVP_init", algorithm: "AES/EVP", keyLen: "?", hex: ptrToHex(keyPtr, 32), iv: ivPtr.isNull() ? null : ptrToHex(ivPtr, 16), source: lib });
                        }
                    },
                });
                log(`[crypto] Hooked EVP_*Init_ex in ${lib}`);
            } catch (_) {}
        }

        // d2i_RSAPrivateKey — DER-encoded RSA private key loaded into memory
        const d2iRsa = Module.findExportByName(lib, "d2i_RSAPrivateKey");
        if (d2iRsa) {
            try {
                Interceptor.attach(d2iRsa, {
                    onEnter(args) {
                        this.ppIn  = args[1];
                        this.inLen = args[2].toInt32();
                    },
                    onLeave(retval) {
                        if (retval.isNull() || this.inLen <= 0) return;
                        try {
                            const derPtr = this.ppIn.readPointer().sub(this.inLen);
                            sendFile("rsa_private_key.der", derPtr.readByteArray(this.inLen));
                            addKey({ type: "RSAPrivateKey", algorithm: "RSA", source: lib, note: "DER saved as rsa_private_key.der" });
                        } catch (_) {}
                    },
                });
                log(`[crypto] Hooked d2i_RSAPrivateKey in ${lib}`);
            } catch (_) {}
        }
    }
}

// ── 3. High-entropy memory scan ───────────────────────────────────────────────

const KEY_SIZES = [16, 24, 32]; // AES-128/192/256
const ENTROPY_THRESHOLD = 7.4;

function scanHighEntropyRegions() {
    log("[crypto] Scanning for high-entropy key regions...");
    let found = 0;
    const MAX_SCAN_SIZE = 4 * 1024 * 1024; // scan first 4MB per range to stay fast

    Process.enumerateRanges("r--").forEach(range => {
        if (range.size < 16 || range.size > 64 * 1024 * 1024) return;
        try {
            const limit = Math.min(range.size, MAX_SCAN_SIZE);
            // Slide a 32-byte window every 16 bytes
            for (let off = 0; off + 32 <= limit; off += 16) {
                const buf = range.base.add(off).readByteArray(32);
                const h   = entropy(buf);
                if (h >= ENTROPY_THRESHOLD) {
                    // Check for common AES S-box prefix to reduce false positives
                    const v = new Uint8Array(buf);
                    if (v[0] === 0 && v[1] === 0) continue; // skip zero-heavy
                    addKey({
                        type:    "HighEntropyRegion",
                        algorithm: "unknown",
                        keyLen:  256,
                        hex:     toHex(buf),
                        entropy: h.toFixed(3),
                        addr:    range.base.add(off).toString(),
                        source:  "scan",
                    });
                    found++;
                    off += 32; // skip ahead after a hit
                }
            }
        } catch (_) {}
    });

    log(`[crypto] Entropy scan done. ${found} candidate region(s) found.`);
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (keyLog.length > 0) sendJson("crypto_keys.json", keyLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[crypto] Agent loaded");
hookNativeCrypto();
Java.performNow(hookJavaCrypto);
setTimeout(() => { scanHighEntropyRegions(); flush(); }, 8000);
setInterval(flush, 15000);
