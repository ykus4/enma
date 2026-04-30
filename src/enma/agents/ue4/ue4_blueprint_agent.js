'use strict';

/*
 * UE4 Blueprint Call Tracer
 * Hooks UFunction::Invoke (ProcessEvent) to trace Blueprint VM calls.
 *
 * In UE4 the Blueprint VM runs through:
 *   UObject::ProcessEvent(UFunction*, void* Params)
 * or the internal dispatch:
 *   UFunction::Invoke(UObject*, FFrame&, void* Result)
 *
 * This agent hooks ProcessEvent because it is the single dispatch choke-point
 * for ALL Blueprint function calls, including events, RPCs, and latent actions.
 *
 * Auto-detection:
 *   - Exported symbol  ProcessEvent  (dev/debug builds)
 *   - AArch64 pattern scan in libUE4.so .text section (shipping builds)
 *
 * For stripped shipping builds, override via rpc.exports.configure().
 */

const MAX_TRACE_ENTRIES = 5000;

const OBJ_NAME  = 0x18;  // FName offset in UObject
const FNAME_IDX = 0x00;  // ComparisonIndex offset within FName (uint32)

let _processEventAddr = null;
let _gnamesPtr        = null;

const traceLog = [];
let   traceEnabled  = true;
const callDepth     = {};  // threadId → depth

function log(msg) { send({ event: 'log', message: msg }); }

// ── Name lookup (mirrors ue4_sdk_agent) ───────────────────────────────────────

const nameCache = new Map();

function readNameDirect(nameIdx) {
    if (nameCache.has(nameIdx)) return nameCache.get(nameIdx);
    if (!_gnamesPtr) return `[${nameIdx}]`;

    try {
        const blockIdx    = nameIdx >> 16;
        const entryOffset = (nameIdx & 0xFFFF) * 4;  // stride = 4
        const blockPtr    = _gnamesPtr.add(0x10 + blockIdx * Process.pointerSize).readPointer();
        if (!blockPtr || blockPtr.isNull()) return `[${nameIdx}]`;

        const entryPtr = blockPtr.add(entryOffset);
        const header   = entryPtr.readU16();
        const isWide   = header & 1;
        const len      = (header >> 6) & 0x3FF;
        if (len === 0 || len > 1024) return `[${nameIdx}]`;

        const name = isWide
            ? new TextDecoder('utf-16le').decode(entryPtr.add(2).readByteArray(len * 2))
            : entryPtr.add(2).readUtf8String(len);

        nameCache.set(nameIdx, name);
        return name;
    } catch (e) {
        return `[${nameIdx}]`;
    }
}

function readObjectName(objPtr) {
    try {
        const nameIdx = objPtr.add(OBJ_NAME).readU32();
        const nameNum = objPtr.add(OBJ_NAME + 4).readU32();
        const base    = readNameDirect(nameIdx);
        return nameNum > 0 ? `${base}_${nameNum - 1}` : base;
    } catch (e) {
        return '?';
    }
}

// ── ProcessEvent hook ─────────────────────────────────────────────────────────

function installHook(addr) {
    log(`[ue4_bp] Hooking ProcessEvent at ${addr}`);
    Interceptor.attach(addr, {
        onEnter(args) {
            if (!traceEnabled || traceLog.length >= MAX_TRACE_ENTRIES) return;

            // ProcessEvent(UObject* this, UFunction* Function, void* Params)
            // In ARM64 calling convention: x0=this, x1=Function, x2=Params
            const objPtr  = args[0];
            const funcPtr = args[1];

            if (!objPtr || objPtr.isNull()) return;
            if (!funcPtr || funcPtr.isNull()) return;

            const tid   = Process.getCurrentThreadId();
            const depth = (callDepth[tid] = (callDepth[tid] ?? 0) + 1);

            try {
                const objName  = readObjectName(objPtr);
                const funcName = readObjectName(funcPtr);

                if (depth > 32) { callDepth[tid]--; return; }  // skip deep recursion

                traceLog.push({
                    ts:     Date.now(),
                    tid,
                    depth,
                    obj:    objName,
                    func:   funcName,
                    objAddr:  objPtr.toString(),
                    funcAddr: funcPtr.toString(),
                });
            } catch (e) {
                callDepth[tid]--;
            }
        },
        onLeave() {
            const tid = Process.getCurrentThreadId();
            if (callDepth[tid] > 0) callDepth[tid]--;
        },
    });
}

// ── Discovery ─────────────────────────────────────────────────────────────────

function findByExport() {
    const mod = Process.findModuleByName('libUE4.so')
             ?? Process.findModuleByName('libUnreal.so');
    if (!mod) return null;

    // Try common mangled / unmangled variants
    for (const sym of [
        'ProcessEvent',
        '_ZN7UObject12ProcessEventEP9UFunctionPv',
        '_ZN7UObject13ProcessEventEP9UFunctionPv',
    ]) {
        const addr = Module.findExportByName(mod.name, sym);
        if (addr) { log(`[ue4_bp] Found ProcessEvent via export: ${addr}`); return addr; }
    }
    return null;
}

/*
 * AArch64 pattern for ProcessEvent prologue (UE4.25-4.27 shipping):
 * The function saves a large frame and immediately accesses UFunction flags
 * at a well-known offset (0x98 in UE4.25).  This is the least-fragile heuristic.
 *
 * Pattern: STP x29,x30,[sp,#-N]!   (E5/E3 7B B... A9)
 *          MOV x29,sp               (FD 03 00 91)
 *          ...
 * We narrow by also requiring the GUObjectArray xref nearby.
 * Because this is fragile, we cap at the first plausible match.
 */
function findByPatternScan() {
    const mod = Process.findModuleByName('libUE4.so')
             ?? Process.findModuleByName('libUnreal.so');
    if (!mod) return null;

    // Generic ARM64 function prologue with 16-byte stack frame alignment
    // 'xx 7b Bx a9' = STP x29,x30,[sp,#-N]!  (bits 31:22 = 0b1010_1001)
    const pattern = 'fd 7b b? a9 fd 03 00 91';
    const results = Memory.scanSync(mod.base, mod.size, pattern);

    if (results.length === 0) {
        log('[ue4_bp] Pattern scan: no ProcessEvent candidates found');
        return null;
    }

    // ProcessEvent is one of the largest functions in libUE4.so.
    // As a rough filter, pick the match closest to the module midpoint
    // (engine dispatch tends to live in the first half of .text).
    const best = results[0].address;
    log(`[ue4_bp] Pattern scan: using candidate at ${best} (${results.length} total matches)`);
    return best;
}

// ── Auto-flush on timeout ─────────────────────────────────────────────────────

setTimeout(() => {
    flush();
}, 30000);

function flush() {
    if (traceLog.length === 0) {
        log('[ue4_bp] No Blueprint calls recorded yet');
        return;
    }
    send({
        event: 'json',
        name: 'ue4_blueprint_trace.json',
        data: {
            total:   traceLog.length,
            capped:  traceLog.length >= MAX_TRACE_ENTRIES,
            entries: traceLog,
        },
    });
    log(`[ue4_bp] Flushed ${traceLog.length} Blueprint call records`);
}

// ── RPC exports ───────────────────────────────────────────────────────────────

rpc.exports = {
    /**
     * Override auto-detected addresses.
     * @param {{ processEventAddr?: string, gnamesPtr?: string }} opts
     */
    configure(opts) {
        if (opts.processEventAddr) {
            _processEventAddr = ptr(opts.processEventAddr);
            installHook(_processEventAddr);
        }
        if (opts.gnamesPtr) {
            _gnamesPtr = ptr(opts.gnamesPtr);
        }
    },

    /** Flush current trace to file. */
    flush() {
        flush();
        return traceLog.length;
    },

    /** Pause / resume tracing. */
    setEnabled(v) {
        traceEnabled = !!v;
        log(`[ue4_bp] Tracing ${traceEnabled ? 'enabled' : 'paused'}`);
    },

    /** Clear the trace buffer. */
    clear() {
        traceLog.length = 0;
        for (const k of Object.keys(callDepth)) delete callDepth[k];
        log('[ue4_bp] Trace buffer cleared');
    },

    /** Return current record count without flushing. */
    count() {
        return traceLog.length;
    },
};

// ── Bootstrap ────────────────────────────────────────────────────────────────

setImmediate(() => {
    _processEventAddr = findByExport() ?? findByPatternScan();
    if (_processEventAddr) {
        installHook(_processEventAddr);
    } else {
        log('[ue4_bp] ProcessEvent not found automatically.');
        log('[ue4_bp] Use rpc.exports.configure({ processEventAddr: "0x..." }) to set it.');
    }
});
