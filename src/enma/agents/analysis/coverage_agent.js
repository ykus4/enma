"use strict";
/**
 * Stalker Code Coverage Agent
 *
 * Uses Frida Stalker to record every basic block executed in the target process.
 * Output: coverage.json  — { blocks: [{module, rva, size}], summary: {module: count} }
 *
 * Usage note: Stalker has overhead. Attach with --spawn or limit to a thread
 * via the threadId filter if performance is critical.
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

const blocks = [];        // { module, rva, size }
const seen   = new Set(); // dedup by address string
const summary = {};       // module -> block count

function addrToRva(addr) {
    for (const mod of Process.enumerateModules()) {
        if (addr.compare(mod.base) >= 0 && addr.compare(mod.base.add(mod.size)) < 0) {
            return { module: mod.name, rva: "0x" + addr.sub(mod.base).toString(16) };
        }
    }
    return { module: "?", rva: addr.toString() };
}

function startStalker(tid) {
    log(`[coverage] Stalking thread ${tid}`);
    Stalker.follow(tid, {
        events: { block: true },
        onReceive(events) {
            const parsed = Stalker.parse(events, { annotate: true, stringify: false });
            for (const ev of parsed) {
                if (ev[0] !== "block") continue;
                const addr = ev[1];
                const key  = addr.toString();
                if (seen.has(key)) continue;
                seen.add(key);
                const size = ev[2] || 0;
                const { module, rva } = addrToRva(addr);
                // Skip system libraries to keep output focused on app code
                if (module.startsWith("libc") || module.startsWith("libdvm") ||
                    module.startsWith("libandroid_runtime")) continue;
                blocks.push({ module, rva, size });
                summary[module] = (summary[module] || 0) + 1;
            }
        },
    });
}

function stopAndFlush() {
    for (const tid of Process.enumerateThreads().map(t => t.id)) {
        try { Stalker.unfollow(tid); } catch (_) {}
    }
    Stalker.flush();
    sendJson("coverage.json", { blocks, summary, totalBlocks: blocks.length });
    log(`[coverage] Done. ${blocks.length} unique basic block(s) across ${Object.keys(summary).length} module(s).`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log("[coverage] Agent loaded — attaching Stalker to all threads");

for (const thread of Process.enumerateThreads()) {
    try { startStalker(thread.id); } catch (e) { log(`[coverage] Stalker attach failed on tid ${thread.id}: ${e}`); }
}

// Flush coverage after 30 s and stop stalking
setTimeout(stopAndFlush, 30000);
// Also flush periodically so data isn't lost on crash
setInterval(() => {
    if (blocks.length > 0) sendJson("coverage.json", { blocks, summary, totalBlocks: blocks.length });
}, 10000);
