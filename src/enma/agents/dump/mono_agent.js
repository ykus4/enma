"use strict";
/**
 * Unity Mono Backend Agent
 *
 * For Unity games compiled with the Mono scripting backend (older titles,
 * or when IL2CPP is disabled). Dumps:
 *   1. All loaded managed assemblies (.dll) via the Mono embedding API.
 *   2. mono_assembly_load / mono_image_open hooks to capture late-loaded DLLs.
 *   3. Raw .NET PE bytes from mapped regions (magic: MZ + PE signature).
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendFile(name, buf) { send({ event: "file", name: name }, buf); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

// ── Helpers ───────────────────────────────────────────────────────────────────

const dumpedNames = new Set();

function dumpAssemblyImage(imagePtr, hint) {
    if (!imagePtr || imagePtr.isNull()) return;

    // mono_image_get_filename returns the file path
    const getFilename = Module.findExportByName("libmono.so", "mono_image_get_filename")
        || Module.findExportByName("libmono-2.0.so", "mono_image_get_filename");
    let name = hint || "unknown.dll";
    if (getFilename) {
        try {
            const fn = new NativeFunction(getFilename, "pointer", ["pointer"]);
            const p  = fn(imagePtr);
            if (!p.isNull()) name = p.readUtf8String().split("/").pop() || name;
        } catch (_) {}
    }

    if (dumpedNames.has(name)) { log(`[mono] Skip duplicate: ${name}`); return; }
    dumpedNames.add(name);

    // mono_image_get_raw_data / mono_image_get_raw_data_len
    const getRaw = Module.findExportByName("libmono.so", "mono_image_get_raw_data")
        || Module.findExportByName("libmono-2.0.so", "mono_image_get_raw_data");
    const getLen = Module.findExportByName("libmono.so", "mono_image_get_raw_data_len")
        || Module.findExportByName("libmono-2.0.so", "mono_image_get_raw_data_len");

    if (getRaw && getLen) {
        try {
            const rawFn = new NativeFunction(getRaw, "pointer", ["pointer"]);
            const lenFn = new NativeFunction(getLen, "uint32",  ["pointer"]);
            const dataPtr = rawFn(imagePtr);
            const size    = lenFn(imagePtr);
            if (!dataPtr.isNull() && size > 0 && size < 64 * 1024 * 1024) {
                log(`[mono] Saving ${name}  size=${size}`);
                sendFile(name, dataPtr.readByteArray(size));
                return;
            }
        } catch (_) {}
    }

    log(`[mono] No raw data API for ${name} — trying PE scan`);
}

// ── Enumerate all loaded assemblies ──────────────────────────────────────────

function enumAssemblies(monoLib) {
    // mono_domain_get_assemblies doesn't exist; use mono_assembly_foreach
    const foreachSym = Module.findExportByName(monoLib, "mono_assembly_foreach");
    if (!foreachSym) { log("[mono] mono_assembly_foreach not found"); return; }

    const imageGetSym = Module.findExportByName(monoLib, "mono_assembly_get_image");
    if (!imageGetSym) { log("[mono] mono_assembly_get_image not found"); return; }

    const assemblyGetImage = new NativeFunction(imageGetSym, "pointer", ["pointer"]);

    // The callback receives (MonoAssembly*, user_data)
    const callback = new NativeCallback(
        (assemblyPtr) => {
            try {
                const img = assemblyGetImage(assemblyPtr);
                dumpAssemblyImage(img, null);
            } catch (_) {}
        },
        "void", ["pointer", "pointer"]
    );

    const foreachFn = new NativeFunction(foreachSym, "void", ["pointer", "pointer"]);
    foreachFn(callback, ptr(0));
    log(`[mono] Assembly enumeration done. Dumped ${dumpedNames.size} DLL(s).`);
}

// ── Hook mono_assembly_load* to catch late loads ──────────────────────────────

function hookMonoLoad(monoLib) {
    const targets = [
        "mono_assembly_load",
        "mono_assembly_load_from",
        "mono_assembly_load_from_full",
        "mono_image_open",
        "mono_image_open_full",
    ];

    const imageGetSym = Module.findExportByName(monoLib, "mono_assembly_get_image");
    const assemblyGetImage = imageGetSym
        ? new NativeFunction(imageGetSym, "pointer", ["pointer"])
        : null;

    for (const sym of targets) {
        const addr = Module.findExportByName(monoLib, sym);
        if (!addr) continue;
        try {
            Interceptor.attach(addr, {
                onLeave(retval) {
                    if (retval.isNull()) return;
                    try {
                        // For mono_image_open* retval is MonoImage*
                        // For mono_assembly_load* retval is MonoAssembly* → get image
                        const img = sym.includes("image")
                            ? retval
                            : (assemblyGetImage ? assemblyGetImage(retval) : retval);
                        dumpAssemblyImage(img, null);
                    } catch (_) {}
                },
            });
            log(`[mono] Hooked ${sym}`);
        } catch (e) {
            log(`[mono] Hook failed for ${sym}: ${e}`);
        }
    }
}

// ── Scan for MZ/PE headers in memory (fallback) ───────────────────────────────

function scanForPeHeaders() {
    log("[mono] Scanning memory for MZ/PE headers...");
    let count = 0;
    const scanned = new Set();

    Process.enumerateRanges("r--").forEach(range => {
        if (range.size < 0x40) return;
        try {
            Memory.scanSync(range.base, range.size, "4D 5A", { // "MZ"
                onMatch(address) {
                    const key = address.toString();
                    if (scanned.has(key)) return;
                    scanned.add(key);
                    try {
                        // Read e_lfanew at offset 0x3C
                        const eLfanew = address.add(0x3C).readU32();
                        if (eLfanew > 0x1000 || eLfanew < 4) return;
                        const peSig = address.add(eLfanew).readU32();
                        if (peSig !== 0x00004550) return; // "PE\0\0"
                        // Read SizeOfImage from Optional Header (offset eLfanew + 4 + 20 + 56)
                        const sizeOfImage = address.add(eLfanew + 0x50).readU32();
                        if (sizeOfImage < 0x1000 || sizeOfImage > 64 * 1024 * 1024) return;
                        const remaining = range.size - address.sub(range.base).toInt32();
                        const sz = Math.min(sizeOfImage, remaining);
                        const name = `pe_scan_${++count}_${address}.dll`;
                        log(`[mono] PE found at ${address}  size=${sz}`);
                        sendFile(name, address.readByteArray(sz));
                    } catch (_) {}
                },
                onError() {},
                onComplete() {},
            });
        } catch (_) {}
    });

    log(`[mono] PE scan done. Found ${count} image(s).`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[mono] Agent loaded");

const monoLib = ["libmono.so", "libmono-2.0.so", "libunity.so"].find(n => !!Process.findModuleByName(n));
if (!monoLib) {
    log("[mono] No Mono library found — not a Mono Unity app");
} else {
    log(`[mono] Found Mono: ${monoLib}`);
    hookMonoLoad(monoLib);
    setTimeout(() => {
        enumAssemblies(monoLib);
        setTimeout(scanForPeHeaders, 2000);
    }, 1500);
}
