"use strict";
/**
 * Java Heap Dump Agent
 *
 * Enumerates live Java heap objects that are security-relevant:
 *   - java.lang.String  (all unique strings, deduped)
 *   - byte[]            (byte arrays likely to contain keys, tokens, certs)
 *   - javax.crypto.SecretKey and subclasses
 *   - java.security.PrivateKey / PublicKey
 *   - android.content.SharedPreferences (key-value pairs)
 *   - okhttp3.Request / okhttp3.Response (URL, headers, body)
 *   - android.net.Uri
 *
 * Output:
 *   heap_strings.json   — unique strings grouped by class that held them
 *   heap_keys.json      — raw key bytes from live SecretKey objects
 *   heap_http.json      — captured HTTP request/response objects
 *   heap_bytes.json     — high-entropy byte[] likely to be keys/tokens
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

// ── Shannon entropy ───────────────────────────────────────────────────────────

function entropy(jbyteArray) {
    const freq = new Array(256).fill(0);
    const len  = jbyteArray.length;
    for (let i = 0; i < len; i++) freq[jbyteArray[i] & 0xff]++;
    let h = 0;
    for (const f of freq) {
        if (f === 0) continue;
        const p = f / len;
        h -= p * Math.log2(p);
    }
    return h;
}

function toHex(jbyteArray) {
    return Array.from(jbyteArray).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
}

// ── String harvest (security-relevant only) ───────────────────────────────────

const STRING_KW = /token|secret|key|password|auth|bearer|api[-_]?key|jwt|credential|session/i;

function harvestStrings() {
    log("[heap] Enumerating security-relevant java.lang.String instances ...");
    const strings = [];
    const seen    = new Set();

    Java.choose("java.lang.String", {
        onMatch(obj) {
            try {
                const s = obj.toString();
                if (s.length < 4 || s.length > 2048) return;
                if (!STRING_KW.test(s)) return;
                if (seen.has(s)) return;
                seen.add(s);
                strings.push(s);
            } catch (_) {}
        },
        onComplete() {
            log(`[heap] Strings: ${strings.length} security-relevant`);
            if (strings.length > 0) sendJson("heap_strings.json", strings);
        },
    });
}

// ── Crypto key harvest ────────────────────────────────────────────────────────

function harvestKeys() {
    log("[heap] Enumerating SecretKey / PrivateKey instances ...");
    const keys = [];

    const targets = [
        "javax.crypto.spec.SecretKeySpec",
        "javax.crypto.SecretKey",
        "java.security.PrivateKey",
        "java.security.interfaces.RSAPrivateKey",
        "javax.crypto.interfaces.PBEKey",
    ];

    for (const cls of targets) {
        try {
            Java.choose(cls, {
                onMatch(obj) {
                    try {
                        const encoded = obj.getEncoded();
                        if (!encoded) return;
                        const hex = toHex(encoded);
                        const alg = obj.getAlgorithm ? obj.getAlgorithm().toString() : cls;
                        keys.push({ class: cls, algorithm: alg, keyLen: encoded.length * 8, hex });
                        log(`[heap] Key: ${cls}  alg=${alg}  ${encoded.length * 8} bits`);
                    } catch (_) {}
                },
                onComplete() {},
            });
        } catch (_) {}
    }

    log(`[heap] Keys: ${keys.length} found`);
    sendJson("heap_keys.json", keys);
}

// ── High-entropy byte[] harvest ───────────────────────────────────────────────

function harvestByteArrays() {
    log("[heap] Enumerating high-entropy byte[] (length 16–256) ...");
    const results = [];
    const seen    = new Set();

    const KEY_SIZES = new Set([16, 20, 24, 32, 48, 64, 128, 256]);

    Java.choose("[B", {  // "[B" is byte[]
        onMatch(obj) {
            try {
                const len = obj.length;
                if (len < 16 || len > 256) return;
                const hex = toHex(obj);
                if (seen.has(hex)) return;
                seen.add(hex);
                const h = entropy(obj);
                if (h < 7.2) return;
                results.push({
                    length:  len,
                    entropy: +h.toFixed(3),
                    isKeySize: KEY_SIZES.has(len),
                    hex,
                });
            } catch (_) {}
        },
        onComplete() {
            // Sort by entropy descending
            results.sort((a, b) => b.entropy - a.entropy);
            log(`[heap] High-entropy byte[]: ${results.length} found`);
            sendJson("heap_bytes.json", results);
        },
    });
}

// ── SharedPreferences harvest ─────────────────────────────────────────────────

function harvestSharedPrefs() {
    log("[heap] Enumerating SharedPreferences ...");
    const prefs = [];

    const SPImpl = [
        "android.app.SharedPreferencesImpl",
        "com.google.android.gms.common.data.BitmapTeleporter",
    ];

    for (const cls of SPImpl) {
        try {
            Java.choose(cls, {
                onMatch(obj) {
                    try {
                        const all = obj.getAll();
                        const map = {};
                        const keySet = all.keySet().toArray();
                        for (let i = 0; i < keySet.length; i++) {
                            const k = keySet[i].toString();
                            const v = all.get(Java.use("java.lang.String").$new(k));
                            map[k] = v ? v.toString() : null;
                        }
                        if (Object.keys(map).length > 0) {
                            prefs.push(map);
                            log(`[heap] SharedPrefs: ${Object.keys(map).length} entries`);
                        }
                    } catch (_) {}
                },
                onComplete() {},
            });
        } catch (_) {}
    }

    if (prefs.length > 0) sendJson("heap_prefs.json", prefs);
}

// ── OkHttp3 request/response harvest ─────────────────────────────────────────

function harvestOkHttp() {
    log("[heap] Enumerating OkHttp3 Request/Response ...");
    const http = [];

    try {
        Java.choose("okhttp3.Request", {
            onMatch(req) {
                try {
                    const url     = req.url().toString();
                    const method  = req.method().toString();
                    const headers = {};
                    const hNames  = req.headers().names().toArray();
                    for (let i = 0; i < hNames.length; i++) {
                        const n = hNames[i].toString();
                        headers[n] = req.header(Java.use("java.lang.String").$new(n)).toString();
                    }
                    http.push({ type: "request", method, url, headers });
                    log(`[heap] OkHttp Request: ${method} ${url}`);
                } catch (_) {}
            },
            onComplete() {},
        });
    } catch (_) {}

    try {
        Java.choose("okhttp3.Response", {
            onMatch(resp) {
                try {
                    const code = resp.code();
                    const url  = resp.request().url().toString();
                    http.push({ type: "response", code, url });
                    log(`[heap] OkHttp Response: ${code} ${url}`);
                } catch (_) {}
            },
            onComplete() {},
        });
    } catch (_) {}

    if (http.length > 0) sendJson("heap_http.json", http);
}

// ── android.net.Uri harvest ───────────────────────────────────────────────────

function harvestUris() {
    log("[heap] Enumerating android.net.Uri ...");
    const uris = [];
    const seen = new Set();

    try {
        Java.choose("android.net.Uri$HierarchicalUri", {
            onMatch(obj) {
                try {
                    const s = obj.toString();
                    if (!seen.has(s)) { seen.add(s); uris.push(s); }
                } catch (_) {}
            },
            onComplete() {},
        });
    } catch (_) {}

    if (uris.length > 0) {
        log(`[heap] URIs: ${uris.length} found`);
        sendJson("heap_uris.json", uris);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[heap] Agent loaded — heap scan scheduled in 5s");

setTimeout(() => {
    Java.perform(() => {
        harvestKeys();
        harvestByteArrays();
        harvestSharedPrefs();
        harvestOkHttp();
        harvestUris();
        harvestStrings(); // last — largest dataset
    });
}, 5000);
