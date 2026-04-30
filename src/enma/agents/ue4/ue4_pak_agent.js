'use strict';

/*
 * UE4 PAK Agent
 * Intercepts PAK file operations at multiple layers:
 *   1. Java android.content.res.AssetManager (APK-embedded .pak)
 *   2. libc open() / fopen() — catches filesystem .pak opens
 *   3. FPakFile constructor export — catches engine-level PAK init
 *
 * Output: ue4_pak_list.json  — list of discovered PAK paths + magic validation
 *         ue4_pak_N.pak      — raw PAK files dumped from memory (if small enough)
 */

const PAK_MAGIC    = 0x5A6F12E1;  // UE4 PAK magic (little-endian)
const PAK_MAX_DUMP = 256 * 1024 * 1024;  // 256 MB max per PAK dump
const PAK_HEADER_SIZE = 53;  // min size for version 8 header parse

const discovered = new Map();  // path → { size, version, valid }

function log(msg) { send({ event: 'log', message: msg }); }

// ── Parse PAK header from ptr ─────────────────────────────────────────────────

function parsePakHeader(ptr) {
    try {
        const magic = ptr.readU32();
        if (magic !== PAK_MAGIC) return null;
        const version = ptr.readS32LE ? ptr.add(4).readS32() : ptr.add(4).readS32();
        return { magic: '0x5A6F12E1', version };
    } catch (e) {
        return null;
    }
}

// ── Hook libc open / fopen ────────────────────────────────────────────────────

function hookLibcOpen() {
    const libc = Process.findModuleByName('libc.so');
    if (!libc) return;

    const hookOpen = (sym) => {
        const addr = Module.findExportByName('libc.so', sym);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    const path = args[0].readUtf8String() ?? '';
                    if (path.endsWith('.pak') || path.includes('.pak!')) {
                        this._path = path;
                    }
                } catch (e) {}
            },
            onLeave(ret) {
                if (!this._path) return;
                const fd = ret.toInt32();
                if (fd < 0) return;
                log(`[ue4_pak] open: ${this._path} (fd=${fd})`);
                recordPakPath(this._path);
            },
        });
    };

    hookOpen('open');
    hookOpen('open64');
    hookOpen('fopen');
}

// ── Hook FPakFile constructor ─────────────────────────────────────────────────

function hookFPakFile() {
    const mod = Process.findModuleByName('libUE4.so')
             ?? Process.findModuleByName('libUnreal.so');
    if (!mod) return;

    // Try exported symbol first
    const ctorSym = Module.enumerateExports(mod.name)
        .find(e => e.name.includes('FPakFile') && e.name.includes('Archive'));

    if (ctorSym) {
        Interceptor.attach(ctorSym.address, {
            onEnter(args) {
                // FPakFile(FArchive*, bool, bool) — first arg is `this`
                // Path is stored in PakFilename field, try to read it
                try {
                    // TArray<TCHAR>/FString at common offsets for UE4
                    const maybeStrPtr = args[0].add(0x08).readPointer();
                    const maybePath   = maybeStrPtr.readUtf8String(512);
                    if (maybePath && maybePath.length > 4) {
                        log(`[ue4_pak] FPakFile ctor: ${maybePath}`);
                        recordPakPath(maybePath);
                    }
                } catch (e) {}
            },
        });
        log('[ue4_pak] Hooked FPakFile ctor via export');
    }
}

// ── Hook AssetManager for embedded PAKs ───────────────────────────────────────

function hookAssetManager() {
    try {
        Java.perform(() => {
            const AssetManager = Java.use('android.content.res.AssetManager');
            AssetManager.open.overload('java.lang.String').implementation = function(name) {
                const stream = this.open(name);
                if (name.endsWith('.pak')) {
                    log(`[ue4_pak] AssetManager.open: ${name}`);
                    recordPakPath(`assets://${name}`);
                }
                return stream;
            };
        });
    } catch (e) {
        log('[ue4_pak] AssetManager hook skipped (no Java runtime)');
    }
}

// ── Scan memory for PAK magic ─────────────────────────────────────────────────

function scanMemoryForPaks() {
    log('[ue4_pak] Scanning readable memory for PAK magic ...');
    const pattern = '5a 6f 12 e1';  // PAK_MAGIC little-endian
    let found = 0;

    for (const r of Process.enumerateRanges('r--')) {
        if (r.size < PAK_HEADER_SIZE) continue;
        const matches = Memory.scanSync(r.base, r.size, pattern);
        for (const m of matches) {
            const header = parsePakHeader(m.address);
            if (!header) continue;
            found++;
            const key = m.address.toString();
            if (!discovered.has(key)) {
                discovered.set(key, { addr: key, version: header.version, source: 'memscan' });
                log(`[ue4_pak] Found PAK at ${key} (version ${header.version})`);
            }
        }
    }

    log(`[ue4_pak] Memory scan complete: ${found} PAK region(s) found`);
}

// ── Record helper ─────────────────────────────────────────────────────────────

function recordPakPath(path) {
    if (!discovered.has(path)) {
        discovered.set(path, { path, source: 'hook' });
        send({
            event: 'json',
            name: 'ue4_pak_list.json',
            data: Array.from(discovered.values()),
        });
    }
}

// ── Dump a PAK file from a file path ─────────────────────────────────────────

function dumpPakFile(path, index) {
    const libc = Process.findModuleByName('libc.so');
    if (!libc) return;

    const openFn  = new NativeFunction(Module.getExportByName('libc.so', 'open'),  'int',  ['pointer', 'int']);
    const readFn  = new NativeFunction(Module.getExportByName('libc.so', 'read'),  'long', ['int', 'pointer', 'long']);
    const closeFn = new NativeFunction(Module.getExportByName('libc.so', 'close'), 'int',  ['int']);
    const lseekFn = new NativeFunction(Module.getExportByName('libc.so', 'lseek'), 'long', ['int', 'long', 'int']);

    const pathBuf = Memory.allocUtf8String(path);
    const fd = openFn(pathBuf, 0);  // O_RDONLY = 0
    if (fd < 0) {
        log(`[ue4_pak] Cannot open ${path} (fd=${fd})`);
        return;
    }

    const size = lseekFn(fd, 0, 2);  // SEEK_END = 2
    lseekFn(fd, 0, 0);               // SEEK_SET = 0

    if (size <= 0 || size > PAK_MAX_DUMP) {
        log(`[ue4_pak] Skipping ${path}: size=${size} (max=${PAK_MAX_DUMP})`);
        closeFn(fd);
        return;
    }

    log(`[ue4_pak] Dumping ${path} (${(size / 1024 / 1024).toFixed(1)} MB) ...`);
    const buf = Memory.alloc(size);
    let total = 0;
    while (total < size) {
        const n = readFn(fd, buf.add(total), size - total);
        if (n <= 0) break;
        total += n;
    }
    closeFn(fd);

    if (total > 0) {
        const name = `ue4_pak_${index}.pak`;
        send({ event: 'file', name }, buf.readByteArray(total));
        log(`[ue4_pak] Dumped ${name} (${total} bytes)`);
    }
}

// ── Flush final list ──────────────────────────────────────────────────────────

function flushList() {
    if (discovered.size === 0) {
        log('[ue4_pak] No PAK files discovered');
        return;
    }
    send({
        event: 'json',
        name: 'ue4_pak_list.json',
        data: Array.from(discovered.values()),
    });
    log(`[ue4_pak] Total discovered: ${discovered.size} PAK location(s)`);
}

// ── RPC exports ───────────────────────────────────────────────────────────────

rpc.exports = {
    /** Trigger memory scan for PAK magic and flush results. */
    scan() {
        scanMemoryForPaks();
        flushList();
        return discovered.size;
    },

    /** Dump PAK files by path. paths = ["/data/app/.../base.apk!/assets/data.pak", ...] */
    dumpPaths(paths) {
        for (let i = 0; i < paths.length; i++) {
            dumpPakFile(paths[i], i);
        }
        return paths.length;
    },

    /** Return current list of discovered PAK locations. */
    list() {
        return Array.from(discovered.values());
    },
};

// ── Auto-install hooks ────────────────────────────────────────────────────────

hookLibcOpen();
hookFPakFile();
hookAssetManager();
log('[ue4_pak] Hooks installed. Waiting for PAK file access ...');
