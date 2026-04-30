'use strict';

/*
 * UE4 SDK Generator — Android ARM64
 * Supported engine versions: UE4.23–4.27 (FNamePool variant)
 *
 * Auto-detection order:
 *   1. Exported symbols (dev / debug builds)
 *   2. Addresses provided via rpc.exports.configure()
 *   3. Heuristic pattern scan (best-effort; may fail on fully stripped builds)
 *
 * For stripped shipping builds, find GNames / GUObjectArray in IDA or Ghidra:
 *   - GNames:    cross-ref the string "None" in .rodata → follow init call
 *   - GObjects:  cross-ref FEngineLoop::PreInit or UObjectBase::AddObject
 * Then call rpc.exports.configure({ gnamesPtr:"0x...", gobjectsPtr:"0x..." })
 */

// ── Struct offsets — tweak for your UE4 version ───────────────────────────────
const CFG = {
    // UObject member offsets (UE4.25-4.27 ARM64 shipping)
    OBJ_FLAGS:  0x08,
    OBJ_INDEX:  0x0C,
    OBJ_CLASS:  0x10,  // UClass*
    OBJ_NAME:   0x18,  // FName = { uint32 ComparisonIndex, uint32 Number }
    OBJ_OUTER:  0x20,  // UObject*

    // FUObjectItem (24 bytes)
    ITEM_OBJ:   0x00,  // UObject*
    ITEM_SIZE:  0x18,

    // TUObjectArray (inside FUObjectArray at +0x10)
    TUA_OBJECTS:    0x00,  // FUObjectItem** (chunk pointer array)
    TUA_MAX_ELEMS:  0x08,  // int32
    TUA_NUM_ELEMS:  0x0C,  // int32
    TUA_MAX_CHUNKS: 0x10,  // int32
    TUA_NUM_CHUNKS: 0x14,  // int32

    // FUObjectArray base → TUObjectArray starts at +0x10
    ARR_TUOA: 0x10,

    // Chunk size: default 64*1024 / sizeof(FUObjectItem) = 2730
    CHUNK_SIZE: Math.floor(65536 / 24),

    // FNamePool (UE4.23+)
    POOL_CURRENT_BLOCK:  0x08,  // uint32
    POOL_CURRENT_CURSOR: 0x0C,  // uint32
    POOL_BLOCKS:         0x10,  // uint8_t* Blocks[8192] (one ptr per block)

    // FNameEntryId encoding: block = id >> 16, byteOffset = (id & 0xFFFF) * stride
    POOL_BLOCK_BITS: 16,
    POOL_STRIDE:     4,   // bytes per FNameEntryId slot (4 in UE4.25+)

    MAX_OBJECTS: 300000,
};

// Runtime override via rpc.exports.configure()
let _gnamesPtr   = null;
let _gobjectsPtr = null;

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(msg) { send({ event: 'log', message: msg }); }

function safeRead(fn) {
    try { return fn(); } catch (e) { return null; }
}

function readPtr(p) { return safeRead(() => p.readPointer()); }
function readU32(p) { return safeRead(() => p.readU32()); }
function readS32(p) { return safeRead(() => p.readS32()); }

// ── FNamePool traversal (UE4.23+) ─────────────────────────────────────────────

function readFNameEntry(entryPtr) {
    const header = safeRead(() => entryPtr.readU16());
    if (header == null || header === 0) return null;
    const isWide = header & 1;
    // UE4.25 format: len at bits 6–15 (10 bits)
    const len = (header >> 6) & 0x3FF;
    if (len === 0 || len > 1024) return null;
    try {
        if (isWide) {
            const bytes = entryPtr.add(2).readByteArray(len * 2);
            return new TextDecoder('utf-16le').decode(bytes);
        }
        return entryPtr.add(2).readUtf8String(len);
    } catch (e) { return null; }
}

function buildNameTable(poolPtr) {
    const table = new Map();  // FNameEntryId → string

    const currentBlock  = readU32(poolPtr.add(CFG.POOL_CURRENT_BLOCK))  ?? 0;
    const currentCursor = readU32(poolPtr.add(CFG.POOL_CURRENT_CURSOR)) ?? 0;
    const blocksBase    = poolPtr.add(CFG.POOL_BLOCKS);

    for (let bi = 0; bi <= currentBlock && bi < 8192; bi++) {
        const blockPtr = readPtr(blocksBase.add(bi * Process.pointerSize));
        if (!blockPtr || blockPtr.isNull()) continue;

        const limit = bi === currentBlock ? currentCursor : (1 << CFG.POOL_BLOCK_BITS);
        let offset = 0;

        while (offset < limit) {
            const entryPtr = blockPtr.add(offset);
            const name = readFNameEntry(entryPtr);

            if (name !== null) {
                // FNameEntryId: block in upper bits, slot index in lower bits
                const nameId = (bi << CFG.POOL_BLOCK_BITS) | (offset / CFG.POOL_STRIDE);
                table.set(nameId, name);
            }

            // Advance: read header again to compute entry size
            const header = safeRead(() => entryPtr.readU16());
            if (!header) break;
            const len    = (header >> 6) & 0x3FF;
            if (len === 0) { offset += 2; continue; }
            const isWide = header & 1;
            const strBytes = isWide ? len * 2 : len;
            // Round up to CFG.POOL_STRIDE alignment
            const entrySize = (2 + strBytes + (CFG.POOL_STRIDE - 1)) & ~(CFG.POOL_STRIDE - 1);
            offset += entrySize;
        }
    }

    log(`[ue4_sdk] Name table: ${table.size} entries`);
    return table;
}

function lookupName(nameTable, comparisonIndex) {
    return nameTable.get(comparisonIndex) ?? `[${comparisonIndex}]`;
}

// ── GObjects traversal ────────────────────────────────────────────────────────

function iterateObjects(gobjectsPtr, nameTable) {
    // FUObjectArray starts at gobjectsPtr; TUObjectArray is at +ARR_TUOA
    const tuoaPtr = gobjectsPtr.add(CFG.ARR_TUOA);

    const chunksPtr = readPtr(tuoaPtr.add(CFG.TUA_OBJECTS));
    const numElems  = readS32(tuoaPtr.add(CFG.TUA_NUM_ELEMS)) ?? 0;

    if (!chunksPtr || chunksPtr.isNull() || numElems === 0) {
        log('[ue4_sdk] GObjects appears empty or unreadable');
        return [];
    }

    log(`[ue4_sdk] Walking ${numElems} objects (chunk size ${CFG.CHUNK_SIZE}) ...`);

    const objects = [];
    const limit = Math.min(numElems, CFG.MAX_OBJECTS);

    for (let i = 0; i < limit; i++) {
        const chunkIdx    = Math.floor(i / CFG.CHUNK_SIZE);
        const indexInChunk = i % CFG.CHUNK_SIZE;

        const chunkPtr = readPtr(chunksPtr.add(chunkIdx * Process.pointerSize));
        if (!chunkPtr || chunkPtr.isNull()) continue;

        const itemPtr = chunkPtr.add(indexInChunk * CFG.ITEM_SIZE);
        const objPtr  = readPtr(itemPtr.add(CFG.ITEM_OBJ));
        if (!objPtr || objPtr.isNull()) continue;

        // Read FName (ComparisonIndex + Number)
        const nameIdx = readU32(objPtr.add(CFG.OBJ_NAME));
        if (nameIdx == null) continue;

        const nameNum = readU32(objPtr.add(CFG.OBJ_NAME + 4)) ?? 0;
        const name    = lookupName(nameTable, nameIdx) + (nameNum > 0 ? `_${nameNum - 1}` : '');

        // Follow ClassPrivate to get class name
        const classPtr = readPtr(objPtr.add(CFG.OBJ_CLASS));
        let className  = '?';
        if (classPtr && !classPtr.isNull() && !classPtr.equals(objPtr)) {
            const classNameIdx = readU32(classPtr.add(CFG.OBJ_NAME));
            if (classNameIdx != null) className = lookupName(nameTable, classNameIdx);
        }

        // Follow OuterPrivate to get package/outer name
        const outerPtr = readPtr(objPtr.add(CFG.OBJ_OUTER));
        let outerName  = '';
        if (outerPtr && !outerPtr.isNull()) {
            const outerNameIdx = readU32(outerPtr.add(CFG.OBJ_NAME));
            if (outerNameIdx != null) outerName = lookupName(nameTable, outerNameIdx);
        }

        objects.push({ name, class: className, outer: outerName, addr: objPtr.toString() });
    }

    return objects;
}

// ── Discovery strategies ───────────────────────────────────────────────────────

function findByExport() {
    const mod = Process.findModuleByName('libUE4.so')
        ?? Process.findModuleByName('libUnreal.so');
    if (!mod) return null;

    let gnames   = Module.findExportByName(mod.name, 'GNames')
                ?? Module.findExportByName(mod.name, '_ZN12FNamePool6GNamesE');
    let gobjects = Module.findExportByName(mod.name, 'GUObjectArray')
                ?? Module.findExportByName(mod.name, '_ZN12FUObjectArray13GUObjectArrayE');

    // Exported symbols may be the variable itself or a pointer-to-variable
    if (gnames) {
        const candidate = readPtr(gnames);
        if (candidate && !candidate.isNull()) gnames = candidate;
    }
    if (gobjects) {
        const candidate = readPtr(gobjects);
        if (candidate && !candidate.isNull()) gobjects = candidate;
    }

    if (gnames || gobjects) {
        log(`[ue4_sdk] Found via exports: GNames=${gnames} GObjects=${gobjects}`);
    }
    return { gnames, gobjects };
}

function findByPatternScan() {
    const mod = Process.findModuleByName('libUE4.so')
             ?? Process.findModuleByName('libUnreal.so');
    if (!mod) return null;

    // Scan for the "None\0" string that is always first in FNamePool block 0.
    // FNameEntry header for "None" (4 chars, narrow, UE4.25 format):
    //   isWide=0, len=4 → header = (4 << 6) | 0 = 0x0100
    // Layout in block 0 at offset 0: 00 01 4E 6F 6E 65 (LE u16 header + "None")
    const nonePattern = '00 01 4e 6f 6e 65';  // header(0x0100 LE) + "None"

    const ranges = Process.enumerateRanges('r--');
    for (const r of ranges) {
        const matches = Memory.scanSync(r.base, r.size, nonePattern);
        for (const m of matches) {
            // m.address should be the start of block 0 in FNamePool
            // FNamePool.Blocks[0] == m.address
            // FNamePool = *(ptr that holds m.address)
            // Search backward in a pointer-aligned scan for a location that holds m.address
            const blockZeroAddr = m.address;

            // Look for a pointer to blockZeroAddr in nearby memory
            for (const sr of ranges) {
                const results = Memory.scanSync(
                    sr.base, sr.size,
                    blockZeroAddr.toMatchPattern()
                );
                for (const res of results) {
                    // The FNamePool.Blocks array starts at +0x10 from pool base
                    // So pool base = res.address - 0x10
                    const poolBase = res.address.sub(CFG.POOL_BLOCKS);
                    const cb = readU32(poolBase.add(CFG.POOL_CURRENT_BLOCK));
                    if (cb != null && cb < 8192) {
                        log(`[ue4_sdk] Pattern scan found FNamePool at ${poolBase}`);
                        return { gnames: poolBase, gobjects: null };
                    }
                }
            }
        }
    }

    log('[ue4_sdk] Pattern scan found nothing useful');
    return null;
}

// ── Main dump ─────────────────────────────────────────────────────────────────

function dump() {
    let gnamesPtr   = _gnamesPtr;
    let gobjectsPtr = _gobjectsPtr;

    if (!gnamesPtr || !gobjectsPtr) {
        const byExport = findByExport();
        if (byExport) {
            gnamesPtr   = gnamesPtr   ?? byExport.gnames;
            gobjectsPtr = gobjectsPtr ?? byExport.gobjects;
        }
    }

    if (!gnamesPtr) {
        const byPattern = findByPatternScan();
        if (byPattern) {
            gnamesPtr   = gnamesPtr   ?? byPattern.gnames;
            gobjectsPtr = gobjectsPtr ?? byPattern.gobjects;
        }
    }

    if (!gnamesPtr) {
        log('[ue4_sdk] GNames not found. Use rpc.exports.configure() to set the address.');
        log('[ue4_sdk] Tip: in IDA/Ghidra, find the string "None" in .rodata and follow xrefs.');
        send({ event: 'json', name: 'ue4_sdk.json', data: { error: 'GNames not found' } });
        return;
    }

    if (!gobjectsPtr) {
        log('[ue4_sdk] GObjects not found. Use rpc.exports.configure() to set the address.');
        log('[ue4_sdk] Name table only mode — no object walk.');
    }

    // Build name table
    const nameTable = buildNameTable(gnamesPtr);

    // Walk objects
    const objects = gobjectsPtr ? iterateObjects(gobjectsPtr, nameTable) : [];

    // Group by class
    const byClass = {};
    for (const obj of objects) {
        if (!byClass[obj.class]) byClass[obj.class] = [];
        byClass[obj.class].push({ name: obj.name, outer: obj.outer, addr: obj.addr });
    }

    // Sort: UClass entries first (the class names the game defines)
    const classNames  = (byClass['Class'] ?? []).map(o => o.name).sort();
    const funcNames   = (byClass['Function'] ?? []).map(o => `${o.outer}::${o.name}`).sort();
    const enumNames   = (byClass['Enum'] ?? []).map(o => o.name).sort();
    const structNames = (byClass['ScriptStruct'] ?? []).map(o => o.name).sort();

    const sdk = {
        stats: {
            totalObjects:  objects.length,
            totalNames:    nameTable.size,
            classes:       classNames.length,
            functions:     funcNames.length,
            enums:         enumNames.length,
            structs:       structNames.length,
        },
        classes:   classNames,
        functions: funcNames,
        enums:     enumNames,
        structs:   structNames,
        byClass,
    };

    log(`[ue4_sdk] Done: ${objects.length} objects, ${classNames.length} classes, ${funcNames.length} functions`);
    send({ event: 'json', name: 'ue4_sdk.json', data: sdk });
}

// ── RPC exports ───────────────────────────────────────────────────────────────

rpc.exports = {
    /**
     * Provide GNames / GObjects addresses when auto-detection fails.
     * @param {{ gnamesPtr?: string, gobjectsPtr?: string, poolStride?: number }} opts
     */
    configure(opts) {
        if (opts.gnamesPtr)   _gnamesPtr   = ptr(opts.gnamesPtr);
        if (opts.gobjectsPtr) _gobjectsPtr = ptr(opts.gobjectsPtr);
        if (opts.poolStride)  CFG.POOL_STRIDE = opts.poolStride;
        log(`[ue4_sdk] Configured: GNames=${_gnamesPtr} GObjects=${_gobjectsPtr}`);
    },

    /** Run the dump and return summary stats. */
    dump() {
        dump();
        return 'done';
    },
};

// Auto-run on load
setImmediate(dump);
