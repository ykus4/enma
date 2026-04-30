"use strict";
/**
 * Protobuf Auto-Decoder Agent
 *
 * Hooks Wire (Square) and protobuf-java serialization/deserialization to
 * capture encoded bytes and attempt automatic field decoding.
 *
 * Decoding strategy:
 *   - Wire: MessageAdapter.encode() / decode()
 *   - protobuf-java: MessageLite.toByteArray() / parseFrom()
 *   - Raw: hook CodedInputStream.readRawBytes() for low-level captures
 *
 * Output: protobuf_log.json — { direction, class, hex, decoded }[]
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const pbLog = [];
const MAX   = 1000;

function toHex(jbytes) {
    return Array.from(jbytes).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
}

// ── Minimal protobuf varint decoder (for field tag inspection) ────────────────

function decodeProtoFields(bytes) {
    // Returns [{fieldNumber, wireType, value}] — best-effort, no schema
    const fields = [];
    let i = 0;
    const arr = Array.from(bytes).map(b => b & 0xff);
    while (i < arr.length) {
        try {
            let varint = 0, shift = 0, b;
            do {
                b = arr[i++];
                varint |= (b & 0x7f) << shift;
                shift += 7;
            } while (b & 0x80);
            const fieldNumber = varint >>> 3;
            const wireType    = varint & 0x7;
            if (fieldNumber === 0) break;

            let value;
            if (wireType === 0) { // varint
                let v = 0; shift = 0;
                do { b = arr[i++]; v |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
                value = v;
            } else if (wireType === 2) { // length-delimited
                let len = 0; shift = 0;
                do { b = arr[i++]; len |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
                const raw = arr.slice(i, i + len);
                value = { len, hex: raw.map(x => x.toString(16).padStart(2, "0")).join("") };
                i += len;
            } else if (wireType === 5) { // 32-bit
                value = arr.slice(i, i + 4).map(x => x.toString(16).padStart(2, "0")).join("");
                i += 4;
            } else if (wireType === 1) { // 64-bit
                value = arr.slice(i, i + 8).map(x => x.toString(16).padStart(2, "0")).join("");
                i += 8;
            } else {
                break; // unknown wire type
            }
            fields.push({ fieldNumber, wireType, value });
            if (fields.length > 64) break; // safety cap
        } catch (_) { break; }
    }
    return fields;
}

function record(dir, cls, jbytes) {
    if (pbLog.length >= MAX) return;
    try {
        const bytes   = Array.from(jbytes).map(b => b & 0xff);
        const hex     = bytes.map(b => b.toString(16).padStart(2, "0")).join("");
        const decoded = decodeProtoFields(bytes);
        pbLog.push({ ts: Date.now(), direction: dir, class: cls, byteLen: bytes.length, hex, decoded });
        log(`[proto] ${dir} ${cls}  ${bytes.length}B  fields=${decoded.length}`);
    } catch (_) {}
}

// ── 1. protobuf-java MessageLite ──────────────────────────────────────────────

function hookProtobufJava() {
    Java.perform(() => {
        // MessageLite.toByteArray() — encoding
        try {
            const ML = Java.use("com.google.protobuf.MessageLite");
            ML.toByteArray.implementation = function () {
                const bytes = this.toByteArray();
                record("encode", this.getClass().getName(), bytes);
                return bytes;
            };
        } catch (_) {}

        // AbstractParser.parseFrom(byte[]) — decoding
        try {
            const AP = Java.use("com.google.protobuf.AbstractParser");
            AP.parseFrom.overload("[B").implementation = function (bytes) {
                record("decode", this.getClass().getName(), bytes);
                return this.parseFrom(bytes);
            };
        } catch (_) {}

        // GeneratedMessageV3 — newer protobuf-java
        try {
            const GM = Java.use("com.google.protobuf.GeneratedMessageV3");
            GM.toByteArray.implementation = function () {
                const bytes = this.toByteArray();
                record("encode", this.getClass().getName(), bytes);
                return bytes;
            };
        } catch (_) {}
    });
}

// ── 2. Wire (Square) ──────────────────────────────────────────────────────────

function hookWire() {
    Java.perform(() => {
        for (const cls of ["com.squareup.wire.ProtoAdapter", "com.squareup.wire.MessageAdapter"]) {
            try {
                const C = Java.use(cls);
                if (C.encode) {
                    C.encode.overload("java.lang.Object").implementation = function (value) {
                        const bytes = this.encode(value);
                        record("encode", cls, bytes);
                        return bytes;
                    };
                }
                if (C.decode) {
                    C.decode.overload("[B").implementation = function (bytes) {
                        record("decode", cls, bytes);
                        return this.decode(bytes);
                    };
                }
            } catch (_) {}
        }
    });
}

// ── 3. okio / OkHttp protobuf body ───────────────────────────────────────────

function hookOkioProto() {
    Java.perform(() => {
        // Detect protobuf content-type in OkHttp responses
        try {
            const RB = Java.use("okhttp3.ResponseBody");
            RB.bytes.implementation = function () {
                const bytes = this.bytes();
                try {
                    const ct = this.contentType()?.toString() ?? "";
                    if (ct.includes("protobuf") || ct.includes("octet-stream")) {
                        record("http_response", "okhttp3.ResponseBody", bytes);
                    }
                } catch (_) {}
                return bytes;
            };
        } catch (_) {}
    });
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (pbLog.length > 0) sendJson("protobuf_log.json", pbLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[proto] Agent loaded");
Java.performNow(() => {
    hookProtobufJava();
    hookWire();
    hookOkioProto();
});

setInterval(flush, 10000);
setTimeout(flush, 60000);
