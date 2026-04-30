"use strict";
/**
 * Function Call Tracer Agent
 *
 * Attaches Interceptor hooks to every export matching a regex pattern (default: all).
 * Logs: function name, module, args (as hex pointers), return value, thread id, depth.
 *
 * The pattern can be overridden by injecting a `TRACER_PATTERN` global before load,
 * or by passing it as the script's `parameters` option from the Python host.
 *
 * Output: trace.json  — array of call records
 */

function log(msg) { send({ event: "log", message: msg }); }
function sendJson(name, data) { send({ event: "json", name: name, data: data }); }

// Pattern injected from host (Python passes via frida Script parameters / env).
// Default: match nothing — user must specify via TRACER_PATTERN or it hooks nothing.
const RAW_PATTERN = (typeof TRACER_PATTERN !== "undefined") ? TRACER_PATTERN : ".*";
const PATTERN     = new RegExp(RAW_PATTERN, "i");
const MAX_ARGS    = 6;   // capture up to 6 arguments
const MAX_RECORDS = 5000;

const traceLog = [];
let   depth    = 0;

function ptrSafe(p) {
    try { return p.toString(); } catch (_) { return "?"; }
}

function hookExport(mod, exp) {
    try {
        Interceptor.attach(exp.address, {
            onEnter(args) {
                this._depth = ++depth;
                this._name  = exp.name;
                this._mod   = mod.name;
                this._tid   = Process.getCurrentThreadId();
                this._args  = [];
                for (let i = 0; i < MAX_ARGS; i++) {
                    try { this._args.push(ptrSafe(args[i])); } catch (_) { break; }
                }
            },
            onLeave(retval) {
                depth--;
                if (traceLog.length >= MAX_RECORDS) return;
                traceLog.push({
                    ts:     Date.now(),
                    tid:    this._tid,
                    depth:  this._depth,
                    module: this._mod,
                    name:   this._name,
                    args:   this._args,
                    ret:    ptrSafe(retval),
                });
                if (traceLog.length % 500 === 0)
                    log(`[tracer] ${traceLog.length} calls recorded`);
            },
        });
    } catch (_) {}
}

function attachToModules() {
    let total = 0;
    for (const mod of Process.enumerateModules()) {
        // Skip system libs unless pattern explicitly references them
        if (!RAW_PATTERN.includes(mod.name) &&
            (mod.path.startsWith("/system") || mod.path.startsWith("/apex"))) continue;
        for (const exp of mod.enumerateExports()) {
            if (exp.type !== "function") continue;
            if (!PATTERN.test(exp.name)) continue;
            hookExport(mod, exp);
            total++;
        }
    }
    log(`[tracer] Hooked ${total} function(s) matching /${RAW_PATTERN}/`);
}

function flush() {
    if (traceLog.length > 0) sendJson("trace.json", traceLog);
}

// ── Entry point ───────────────────────────────────────────────────────────────

log(`[tracer] Agent loaded. Pattern: /${RAW_PATTERN}/`);
attachToModules();
setInterval(flush, 10000);
setTimeout(flush, 60000);
