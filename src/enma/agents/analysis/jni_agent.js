"use strict";
/**
 * JNI Bridge Agent
 *
 * Hooks RegisterNatives to capture Java method → native function mappings.
 * Falls back to JNIEnv vtable slot 215 when the libart symbol is unavailable.
 * Also enumerates JNI_OnLoad for every loaded native library.
 *
 * Output: jni_map.json
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const jniMap = [];
const seenAddresses = new Set();

// ── JNI type descriptor parser ────────────────────────────────────────────────

const PRIMITIVES = { Z: "boolean", B: "byte", C: "char", S: "short",
                     I: "int", J: "long", F: "float", D: "double", V: "void" };

function jniTypeToJava(sig) {
    if (PRIMITIVES[sig]) return PRIMITIVES[sig];
    if (sig.startsWith("L")) return sig.slice(1, -1).replace(/\//g, ".");
    if (sig.startsWith("[")) return jniTypeToJava(sig.slice(1)) + "[]";
    return sig;
}

function parseDescriptor(desc) {
    const m = desc.match(/^\(([^)]*)\)(.+)$/);
    if (!m) return { params: [], ret: "?" };
    const params = [];
    let i = 0;
    const p = m[1];
    while (i < p.length) {
        if (p[i] === "L") {
            const end = p.indexOf(";", i);
            params.push(jniTypeToJava(p.slice(i, end + 1)));
            i = end + 1;
        } else if (p[i] === "[") {
            let j = i + 1;
            while (j < p.length && p[j] === "[") j++;
            if (p[j] === "L") {
                const end = p.indexOf(";", j);
                params.push(jniTypeToJava(p.slice(i, end + 1)));
                i = end + 1;
            } else {
                params.push(jniTypeToJava(p.slice(i, j + 1)));
                i = j + 1;
            }
        } else {
            params.push(jniTypeToJava(p[i]));
            i++;
        }
    }
    return { params, ret: jniTypeToJava(m[2]) };
}

function addrToRva(addr) {
    for (const mod of Process.enumerateModules()) {
        if (addr.compare(mod.base) >= 0 && addr.compare(mod.base.add(mod.size)) < 0)
            return { module: mod.name, rva: "0x" + addr.sub(mod.base).toString(16) };
    }
    return { module: "?", rva: addr.toString() };
}

// ── Parse JNINativeMethod array ───────────────────────────────────────────────

function parseNativeMethods(methods, count, className) {
    for (let i = 0; i < count; i++) {
        try {
            const base    = methods.add(i * Process.pointerSize * 3);
            const namePtr = base.readPointer();
            const sigPtr  = base.add(Process.pointerSize).readPointer();
            const fnPtr   = base.add(Process.pointerSize * 2).readPointer();
            const addrHex = fnPtr.toString();

            if (seenAddresses.has(addrHex)) continue;
            seenAddresses.add(addrHex);

            const methodName = namePtr.readUtf8String();
            const descriptor = sigPtr.readUtf8String();
            const { params, ret } = parseDescriptor(descriptor);
            const { module, rva } = addrToRva(fnPtr);

            const entry = { javaClass: className, javaMethod: methodName, descriptor,
                            returnType: ret, params, nativeAddress: addrHex, module, rva };
            jniMap.push(entry);
            log(`[jni] ${className}.${methodName}${descriptor} -> ${module}!${rva}`);
        } catch (_) {}
    }
}

// ── Hook RegisterNatives ──────────────────────────────────────────────────────

function hookRegisterNatives() {
    const sym =
        Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPKN3art12JNINativeMethodEi")
        || Module.findExportByName("libart.so", "RegisterNatives");

    if (!sym) {
        log("[jni] RegisterNatives symbol not found — trying vtable hook");
        hookViaVtable();
        return;
    }

    Interceptor.attach(sym, {
        onEnter(args) {
            this.clazz   = args[1];
            this.methods = args[2];
            this.count   = args[3].toInt32();
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return; // JNI_OK == 0
            try {
                const className = Java.vm.getEnv().getClassName(this.clazz).replace(/\//g, ".");
                parseNativeMethods(this.methods, this.count, className);
            } catch (e) { log(`[jni] Parse error: ${e}`); }
        },
    });

    log("[jni] RegisterNatives hook installed");
}

// ── Vtable fallback (slot 215) ────────────────────────────────────────────────

function hookViaVtable() {
    Java.perform(() => {
        try {
            const env    = Java.vm.getEnv().handle;
            const fnAddr = env.readPointer().add(215 * Process.pointerSize).readPointer();
            log(`[jni] RegisterNatives via vtable: ${fnAddr}`);

            Interceptor.attach(fnAddr, {
                onEnter(args) {
                    this.clazz   = args[1];
                    this.methods = args[2];
                    this.count   = args[3].toInt32();
                },
                onLeave() {
                    try {
                        const className = Java.vm.getEnv().getClassName(this.clazz).replace(/\//g, ".");
                        parseNativeMethods(this.methods, this.count, className);
                    } catch (_) {}
                },
            });
            log("[jni] RegisterNatives vtable hook installed");
        } catch (e) { log(`[jni] Vtable hook failed: ${e}`); }
    });
}

// ── Enumerate JNI_OnLoad ──────────────────────────────────────────────────────

function scanJniOnLoad() {
    log("[jni] Scanning loaded modules for JNI_OnLoad ...");
    for (const mod of Process.enumerateModules()) {
        const onLoad = Module.findExportByName(mod.name, "JNI_OnLoad");
        if (!onLoad) continue;
        const { module, rva } = addrToRva(onLoad);
        log(`[jni] JNI_OnLoad: ${module}!${rva}`);
        jniMap.push({
            javaClass: "<JNI_OnLoad>",
            javaMethod: "JNI_OnLoad",
            descriptor: "(JavaVM*, void*) -> jint",
            nativeAddress: onLoad.toString(),
            module,
            rva,
        });
    }
}

// ── Flush ─────────────────────────────────────────────────────────────────────

function flush() {
    if (jniMap.length > 0) {
        sendJson("jni_map.json", jniMap);
        log(`[jni] Flushed ${jniMap.length} JNI mapping(s)`);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[jni] Agent loaded");
hookRegisterNatives();
scanJniOnLoad();

setTimeout(flush, 5000);
setInterval(flush, 20000);
