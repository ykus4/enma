"use strict";
/**
 * IL2CPP Dump Agent
 *
 * Dumps:
 *   1. libil2cpp.so  — compiled IL2CPP native library (raw ELF)
 *   2. global-metadata.dat — Unity metadata
 *   3. il2cpp_dump.json — Il2CppDumper-compatible symbol map
 *      { ScriptMethod[], ScriptString[], ScriptMetadata[], ScriptMetadataMethod[] }
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendFile(name, buf) { send({ event: "file", name: name }, buf); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

// ── Dump ELF module ───────────────────────────────────────────────────────────

function dumpModule(mod) {
    log(`[il2cpp] Dumping ${mod.name}  base=${mod.base}  size=${mod.size}`);
    try {
        sendFile(mod.name, mod.base.readByteArray(mod.size));
    } catch (e) {
        log(`[il2cpp] Failed to read ${mod.name}: ${e}`);
    }
}

// ── Find and dump global-metadata.dat ────────────────────────────────────────

function findAndDumpMetadata() {
    // Strategy A: /proc/self/maps
    try {
        const maps = new File("/proc/self/maps", "r");
        let line;
        while ((line = maps.readLine()) !== null && line !== "") {
            if (!line.includes("global-metadata.dat")) continue;
            const parts    = line.trim().split(/\s+/);
            const [s, e]   = parts[0].split("-");
            const start    = ptr("0x" + s);
            const size     = parseInt(e, 16) - parseInt(s, 16);
            log(`[il2cpp] global-metadata.dat via maps: size=${size}`);
            try { sendFile("global-metadata.dat", start.readByteArray(size)); } catch (_) {}
            maps.close();
            return;
        }
        maps.close();
    } catch (_) {}

    // Strategy B: Java File API
    Java.perform(() => {
        try {
            const ctx      = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const dataDir  = ctx.getApplicationInfo().dataDir.value;
            const JFile    = Java.use("java.io.File");
            const JFis     = Java.use("java.io.FileInputStream");
            const candidates = [
                dataDir + "/assets/bin/Data/Managed/Metadata/global-metadata.dat",
                dataDir + "/il2cpp/Metadata/global-metadata.dat",
                "/data/app/" + ctx.getPackageName().value + "-1/assets/bin/Data/Managed/Metadata/global-metadata.dat",
            ];
            for (const p of candidates) {
                const f = JFile.$new(p);
                if (!f.exists()) continue;
                log(`[il2cpp] Reading metadata from ${p}`);
                const len  = Number(f.length());
                const fis  = JFis.$new(f);
                const jbuf = Java.array("byte", new Array(len).fill(0));
                fis.read(jbuf);
                fis.close();
                const ab = new ArrayBuffer(len);
                new Uint8Array(ab).set(jbuf.map(b => b & 0xff));
                sendFile("global-metadata.dat", ab);
                return;
            }
            log("[il2cpp] global-metadata.dat not found in known paths");
        } catch (e) {
            log(`[il2cpp] Metadata Java fallback error: ${e}`);
        }
    });
}

// ── IL2CPP API resolver ───────────────────────────────────────────────────────

function resolveIl2Cpp(name, retType, argTypes) {
    const addr = Module.findExportByName("libil2cpp.so", name);
    if (!addr) return null;
    return new NativeFunction(addr, retType, argTypes);
}

// ── Build Il2CppDumper-compatible JSON ────────────────────────────────────────

function buildSymbolMap(il2cppBase) {
    log("[il2cpp] Building symbol map...");

    const fn = {
        domain_get:            resolveIl2Cpp("il2cpp_domain_get",                   "pointer", []),
        domain_get_assemblies: resolveIl2Cpp("il2cpp_domain_get_assemblies",        "pointer", ["pointer", "pointer"]),
        assembly_get_image:    resolveIl2Cpp("il2cpp_assembly_get_image",           "pointer", ["pointer"]),
        image_get_name:        resolveIl2Cpp("il2cpp_image_get_name",               "pointer", ["pointer"]),
        image_get_class_count: resolveIl2Cpp("il2cpp_image_get_class_count",        "uint32",  ["pointer"]),
        image_get_class:       resolveIl2Cpp("il2cpp_image_get_class",              "pointer", ["pointer", "uint32"]),
        class_get_name:        resolveIl2Cpp("il2cpp_class_get_name",               "pointer", ["pointer"]),
        class_get_namespace:   resolveIl2Cpp("il2cpp_class_get_namespace",          "pointer", ["pointer"]),
        class_get_methods:     resolveIl2Cpp("il2cpp_class_get_methods",            "pointer", ["pointer", "pointer"]),
        class_get_fields:      resolveIl2Cpp("il2cpp_class_get_fields",             "pointer", ["pointer", "pointer"]),
        class_get_parent:      resolveIl2Cpp("il2cpp_class_get_parent",             "pointer", ["pointer"]),
        class_is_valuetype:    resolveIl2Cpp("il2cpp_class_is_valuetype",           "bool",    ["pointer"]),
        class_is_enum:         resolveIl2Cpp("il2cpp_class_is_enum",                "bool",    ["pointer"]),
        method_get_name:       resolveIl2Cpp("il2cpp_method_get_name",              "pointer", ["pointer"]),
        method_get_return_type:resolveIl2Cpp("il2cpp_method_get_return_type",       "pointer", ["pointer"]),
        method_get_param_count:resolveIl2Cpp("il2cpp_method_get_param_count",       "uint32",  ["pointer"]),
        method_get_param:      resolveIl2Cpp("il2cpp_method_get_param",             "pointer", ["pointer", "uint32"]),
        method_get_param_name: resolveIl2Cpp("il2cpp_method_get_param_name",        "pointer", ["pointer", "uint32"]),
        method_is_static:      resolveIl2Cpp("il2cpp_method_is_static",             "bool",    ["pointer"]),
        type_get_name:         resolveIl2Cpp("il2cpp_type_get_name",                "pointer", ["pointer"]),
        field_get_name:        resolveIl2Cpp("il2cpp_field_get_name",               "pointer", ["pointer"]),
        field_get_type:        resolveIl2Cpp("il2cpp_field_get_type",               "pointer", ["pointer"]),
        field_get_offset:      resolveIl2Cpp("il2cpp_field_get_offset",             "int32",   ["pointer"]),
        field_is_static:       null, // no direct export; derived from offset == -1
    };

    if (!fn.domain_get) {
        log("[il2cpp] il2cpp_domain_get not found — cannot build symbol map");
        return null;
    }

    // Il2CppDumper output format
    const out = {
        ScriptMethod:         [],
        ScriptString:         [],
        ScriptMetadata:       [],
        ScriptMetadataMethod: [],
    };

    const readStr = p => { try { return p.readUtf8String() || ""; } catch (_) { return ""; } };
    const rva     = addr => "0x" + addr.sub(il2cppBase).toString(16);

    try {
        const domain     = fn.domain_get();
        const countPtr   = Memory.alloc(4);
        const assemblies = fn.domain_get_assemblies(domain, countPtr);
        const asmCount   = countPtr.readU32();
        log(`[il2cpp] ${asmCount} assemblies`);

        for (let ai = 0; ai < asmCount; ai++) {
            const asm      = assemblies.add(ai * Process.pointerSize).readPointer();
            const img      = fn.assembly_get_image(asm);
            const imgName  = fn.image_get_name ? readStr(fn.image_get_name(img)) : `img${ai}`;
            const clsCount = fn.image_get_class_count(img);
            log(`[il2cpp] ${imgName}: ${clsCount} classes`);

            for (let ci = 0; ci < clsCount; ci++) {
                const klass  = fn.image_get_class(img, ci);
                const ns     = fn.class_get_namespace ? readStr(fn.class_get_namespace(klass)) : "";
                const name   = fn.class_get_name      ? readStr(fn.class_get_name(klass))      : `C${ci}`;
                const fullName = ns ? `${ns}.${name}` : name;

                const isValue = fn.class_is_valuetype ? fn.class_is_valuetype(klass) : false;
                const isEnum  = fn.class_is_enum      ? fn.class_is_enum(klass)      : false;

                let parentName = "";
                if (fn.class_get_parent) {
                    try {
                        const parent = fn.class_get_parent(klass);
                        if (!parent.isNull() && fn.class_get_name)
                            parentName = readStr(fn.class_get_name(parent));
                    } catch (_) {}
                }

                // Methods
                if (fn.class_get_methods) {
                    const iter = Memory.alloc(Process.pointerSize);
                    iter.writePointer(ptr(0));
                    let method;
                    while (!(method = fn.class_get_methods(klass, iter)).isNull()) {
                        try {
                            const mName    = fn.method_get_name    ? readStr(fn.method_get_name(method))    : "?";
                            const isStatic = fn.method_is_static   ? fn.method_is_static(method)            : false;
                            // method pointer is first field of MethodInfo
                            const fnPtr    = method.readPointer();
                            if (fnPtr.isNull()) continue;
                            const address  = rva(fnPtr);

                            let retType = "void";
                            if (fn.method_get_return_type && fn.type_get_name) {
                                try { retType = readStr(fn.type_get_name(fn.method_get_return_type(method))); } catch (_) {}
                            }

                            const params = [];
                            if (fn.method_get_param_count && fn.method_get_param && fn.type_get_name) {
                                const pc = fn.method_get_param_count(method);
                                for (let pi = 0; pi < pc; pi++) {
                                    try {
                                        const pType = readStr(fn.type_get_name(fn.method_get_param(method, pi)));
                                        const pName = fn.method_get_param_name ? readStr(fn.method_get_param_name(method, pi)) : `p${pi}`;
                                        params.push({ type: pType, name: pName });
                                    } catch (_) {}
                                }
                            }

                            out.ScriptMethod.push({
                                Address: address,
                                Name:    `${fullName}$$${mName}`,
                                Signature: `${retType} ${fullName}::${mName}(${params.map(p => `${p.type} ${p.name}`).join(", ")})`,
                                TypeName: fullName,
                                IsStatic: isStatic,
                            });
                        } catch (_) {}
                    }
                }

                // Fields -> ScriptMetadata
                if (fn.class_get_fields) {
                    const iter = Memory.alloc(Process.pointerSize);
                    iter.writePointer(ptr(0));
                    let field;
                    while (!(field = fn.class_get_fields(klass, iter)).isNull()) {
                        try {
                            const fName   = fn.field_get_name   ? readStr(fn.field_get_name(field))   : "?";
                            const fOffset = fn.field_get_offset ? fn.field_get_offset(field)           : -1;
                            let fType = "?";
                            if (fn.field_get_type && fn.type_get_name) {
                                try { fType = readStr(fn.type_get_name(fn.field_get_type(field))); } catch (_) {}
                            }
                            out.ScriptMetadata.push({
                                Address: "0x" + fOffset.toString(16),
                                Name:    `${fullName}.${fName}`,
                                TypeName: fullName,
                                FieldType: fType,
                                IsStatic: fOffset === -1,
                            });
                        } catch (_) {}
                    }
                }
            }
        }
    } catch (e) {
        log(`[il2cpp] Symbol walk error: ${e}\n${e.stack}`);
    }

    log(`[il2cpp] Symbol map: ${out.ScriptMethod.length} methods, ${out.ScriptMetadata.length} fields`);
    return out;
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[il2cpp] Agent loaded");

const il2cppMod = Process.findModuleByName("libil2cpp.so");
if (!il2cppMod) {
    log("[il2cpp] libil2cpp.so not found — not an IL2CPP app or not yet loaded");
} else {
    log(`[il2cpp] Found libil2cpp.so  base=${il2cppMod.base}  size=${il2cppMod.size}`);
    dumpModule(il2cppMod);
    findAndDumpMetadata();

    setTimeout(() => {
        const map = buildSymbolMap(il2cppMod.base);
        if (map) sendJson("il2cpp_dump.json", map);
    }, 2000);
}
