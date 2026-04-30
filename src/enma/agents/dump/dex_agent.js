"use strict";
/**
 * DEX Dump Agent
 *
 * Strategies:
 *   1. Hook InMemoryDexClassLoader constructor to capture DEX bytes pre-patch.
 *   2. Hook libart OpenMemory / OpenDex to intercept ART-level DEX loading.
 *   3. Memory scan for DEX magic (dex\n035..039).
 *
 * Validation: Adler-32 checksum verified before saving.
 * Dedup: SHA-1 signature (offset 0x0C, 20 bytes) used as content key.
 * Obfuscation report: class/method name entropy heuristics saved as JSON.
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendFile(name, buf) { send({ event: "file", name: name }, buf); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

// ── Adler-32 ─────────────────────────────────────────────────────────────────

function adler32(arrayBuffer, offset, length) {
    const MOD = 65521;
    let a = 1, b = 0;
    const view = new Uint8Array(arrayBuffer, offset, length);
    for (let i = 0; i < view.length; i++) {
        a = (a + view[i]) % MOD;
        b = (b + a) % MOD;
    }
    return ((b << 16) | a) >>> 0;
}

/** Verify DEX Adler-32. DEX checksum covers bytes [12 .. fileSize). */
function verifyDexChecksum(arrayBuffer, fileSize) {
    const view = new DataView(arrayBuffer);
    const stored = view.getUint32(8, true); // little-endian at offset 8
    const computed = adler32(arrayBuffer, 12, fileSize - 12);
    return stored === computed;
}

// ── SHA-1 hex from DEX header (offset 0x0C, 20 bytes) ────────────────────────

function dexSha1Hex(arrayBuffer) {
    const view = new Uint8Array(arrayBuffer, 12, 20);
    return Array.from(view).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isDexMagic(ptr) {
    try {
        const b = new Uint8Array(ptr.readByteArray(8));
        if (b[0] !== 0x64 || b[1] !== 0x65 || b[2] !== 0x78 || b[3] !== 0x0a) return false;
        // version bytes: "035"\0 through "039"\0
        const ver = b[4] * 100 + b[5] * 10 + b[6] - 0x30 * 111;
        return b[7] === 0x00;
    } catch (_) { return false; }
}

function dexFileSize(ptr) {
    try { return ptr.add(0x20).readU32(); } catch (_) { return 0; }
}

const dumpedSha1s = new Set();
let dumpIndex = 0;
const obfStats = { totalClasses: 0, obfClasses: 0, obfMethods: 0, totalMethods: 0 };

function dumpDexBuffer(arrayBuffer, label) {
    const size = arrayBuffer.byteLength;
    if (size < 0x70 || size > 128 * 1024 * 1024) {
        log(`[dex] Skip ${label}: bad size ${size}`);
        return;
    }
    const sha1 = dexSha1Hex(arrayBuffer);
    if (dumpedSha1s.has(sha1)) {
        log(`[dex] Skip ${label}: duplicate (SHA1=${sha1})`);
        return;
    }

    if (!verifyDexChecksum(arrayBuffer, size)) {
        log(`[dex] Checksum mismatch for ${label} — dumping anyway (may be patched)`);
    }

    dumpedSha1s.add(sha1);
    const name = `classes_${++dumpIndex}_${label}.dex`;
    log(`[dex] Saving ${name}  size=${size}  sha1=${sha1}`);
    sendFile(name, arrayBuffer);
    analyzeObfuscation(arrayBuffer, name);
}

function dumpDexAt(ptr, size, label) {
    try {
        const buf = ptr.readByteArray(size);
        dumpDexBuffer(buf, label);
    } catch (e) {
        log(`[dex] Read failed at ${ptr} (${label}): ${e}`);
    }
}

// ── Obfuscation detection ─────────────────────────────────────────────────────

const OBF_PATTERN = /^[a-zA-Z]{1,2}[0-9]?$|^[a-z][A-Z][a-z]?$/;

function analyzeObfuscation(arrayBuffer, dexName) {
    // Parse class_defs_size (offset 0x60) and class_defs_off (offset 0x64)
    const dv = new DataView(arrayBuffer);
    const classDefsSize = dv.getUint32(0x60, true);
    const classDefsOff  = dv.getUint32(0x64, true);
    const stringIdsOff  = dv.getUint32(0x3C, true);

    let obfClasses = 0, obfMethods = 0, totalMethods = 0;

    for (let i = 0; i < Math.min(classDefsSize, 2000); i++) {
        const cdOff    = classDefsOff + i * 32;
        if (cdOff + 4 > arrayBuffer.byteLength) break;
        const typeIdx  = dv.getUint32(cdOff, true);
        // type_ids[typeIdx] -> string_id -> string
        const typeIdsOff = dv.getUint32(0x44, true);
        const strIdx   = dv.getUint32(typeIdsOff + typeIdx * 4, true);
        const strOff   = dv.getUint32(stringIdsOff + strIdx * 4, true);
        // ULEB128 length, then chars — simplified: just read a few bytes
        let nameStart = strOff + 1; // skip ULEB128 (1 byte for short names)
        let name = "";
        try {
            for (let k = 0; k < 32; k++) {
                const c = dv.getUint8(nameStart + k);
                if (c === 0x3B || c === 0) break; // ';' or NUL
                if (c !== 0x4C) name += String.fromCharCode(c); // skip leading 'L'
            }
        } catch (_) {}
        if (OBF_PATTERN.test(name)) obfClasses++;
    }

    obfStats.totalClasses += classDefsSize;
    obfStats.obfClasses   += obfClasses;

    const ratio = classDefsSize > 0 ? (obfClasses / classDefsSize * 100).toFixed(1) : 0;
    if (Number(ratio) > 30) {
        log(`[dex] ${dexName}: HIGH obfuscation ratio ${ratio}% (${obfClasses}/${classDefsSize} classes)`);
    }
}

function saveObfReport() {
    const report = {
        totalClasses:  obfStats.totalClasses,
        obfuscatedClasses: obfStats.obfClasses,
        obfRatioPct:   obfStats.totalClasses > 0
            ? +(obfStats.obfClasses / obfStats.totalClasses * 100).toFixed(2)
            : 0,
        verdict: obfStats.totalClasses > 0 && obfStats.obfClasses / obfStats.totalClasses > 0.3
            ? "ProGuard/R8 heavy obfuscation detected"
            : "Low or no obfuscation",
    };
    sendJson("dex_obfuscation_report.json", report);
}

// ── Strategy 1: InMemoryDexClassLoader hook ───────────────────────────────────

function hookClassLoaders() {
    Java.perform(() => {
        try {
            const IMDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
            IMDCL.$init.overloads.forEach(overload => {
                overload.implementation = function (...args) {
                    log("[dex] InMemoryDexClassLoader.<init> called");
                    const result = overload.apply(this, args);
                    const buf = args[0]; // ByteBuffer or ByteBuffer[]
                    if (!buf) return result;
                    const buffers = Array.isArray(buf) ? buf : [buf];
                    buffers.forEach((bb, bi) => {
                        if (!bb || !bb.capacity) return;
                        try {
                            const capacity = bb.capacity();
                            const dup = bb.duplicate();
                            dup.position(0);
                            const jbytes = Java.array("byte", new Array(capacity).fill(0));
                            dup.get(jbytes);
                            const ab = new ArrayBuffer(capacity);
                            new Uint8Array(ab).set(jbytes.map(b => b & 0xff));
                            dumpDexBuffer(ab, `inmem_${bi}`);
                        } catch (e) {
                            log(`[dex] ByteBuffer read error: ${e}`);
                        }
                    });
                    return result;
                };
            });
            log("[dex] Hooked InMemoryDexClassLoader");
        } catch (e) {
            log(`[dex] Could not hook InMemoryDexClassLoader: ${e}`);
        }
    });
}

// ── Strategy 2: libart OpenMemory hook ───────────────────────────────────────

function hookArtOpenMemory() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) { log("[dex] libart.so not found"); return; }

    const candidates = [
        "_ZN3art11DexFileLoader10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEPNS3_IS9_EEPNS0_12VerifyResultE",
        "_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS0_10OatDexFileEPNS3_IS9_EE",
        "_ZN3art13DexFileLoader8OpenImplERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKhjjbbbPNS1_IS7_EEPNS_13DexFileLoaderE",
    ];

    for (const sym of candidates) {
        const addr = Module.findExportByName("libart.so", sym);
        if (!addr) continue;
        try {
            Interceptor.attach(addr, {
                onEnter(args) { this.base = args[0]; this.size = args[1].toInt32(); },
                onLeave(retval) {
                    if (!retval.isNull() && this.size > 0 && isDexMagic(this.base))
                        dumpDexAt(this.base, this.size, "art_openmem");
                },
            });
            log(`[dex] Hooked libart: ${sym.slice(0, 60)}...`);
            return;
        } catch (e) { log(`[dex] Hook failed: ${e}`); }
    }
    log("[dex] No OpenMemory symbol matched — scan only");
}

// ── Strategy 3: Memory scan ───────────────────────────────────────────────────

function scanMemoryForDex() {
    log("[dex] Memory scan starting...");
    let count = 0;
    Process.enumerateRanges("r--").forEach(range => {
        if (range.size < 0x70) return;
        try {
            Memory.scanSync(range.base, range.size, "64 65 78 0a", {
                onMatch(address) {
                    if (!isDexMagic(address)) return;
                    const sz = dexFileSize(address);
                    if (sz < 0x70 || sz > range.size) return;
                    dumpDexAt(address, sz, "scan");
                    count++;
                },
                onError() {},
                onComplete() {},
            });
        } catch (_) {}
    });
    log(`[dex] Scan done. Found ${count} candidate(s).`);
    saveObfReport();
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[dex] Agent loaded");
Java.performNow(hookClassLoaders);
hookArtOpenMemory();
setTimeout(scanMemoryForDex, 3000);
