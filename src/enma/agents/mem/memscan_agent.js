"use strict";
/**
 * memscan_agent — CheatEngine-style memory value scanner.
 *
 * RPC exports (called from Python):
 *   scan(value, type)          — first scan; returns {count, id}
 *   filter(value, filterType)  — narrow results (eq/gt/lt/changed/unchanged)
 *   results(max)               — return current result list [{addr, value}]
 *   reset()                    — clear all results
 *   info()                     — return scan state summary
 *
 * Supported types: "int8","int16","int32","int64","float","double","bytes"
 * Filter types:    "eq","ne","gt","lt","gte","lte","changed","unchanged"
 */

const MAX_RESULTS = 100000;
const SCAN_CHUNK  = 0x100000;  // 1 MB at a time

// ── Type descriptors ──────────────────────────────────────────────────────────

const TYPES = {
  int8:   { size: 1, read: (p) => p.readS8(),      write: (p, v) => p.writeS8(v)      },
  int16:  { size: 2, read: (p) => p.readS16(),     write: (p, v) => p.writeS16(v)     },
  int32:  { size: 4, read: (p) => p.readS32(),     write: (p, v) => p.writeS32(v)     },
  int64:  { size: 8, read: (p) => p.readS64(),     write: (p, v) => p.writeS64(v)     },
  uint8:  { size: 1, read: (p) => p.readU8(),      write: (p, v) => p.writeU8(v)      },
  uint16: { size: 2, read: (p) => p.readU16(),     write: (p, v) => p.writeU16(v)     },
  uint32: { size: 4, read: (p) => p.readU32(),     write: (p, v) => p.writeU32(v)     },
  uint64: { size: 8, read: (p) => p.readU64(),     write: (p, v) => p.writeU64(v)     },
  float:  { size: 4, read: (p) => p.readFloat(),   write: (p, v) => p.writeFloat(v)   },
  double: { size: 8, read: (p) => p.readDouble(),  write: (p, v) => p.writeDouble(v)  },
  bytes:  { size: 0, read: null,                   write: null                         },
};

// ── State ─────────────────────────────────────────────────────────────────────

let _results   = [];   // [{addr: NativePointer, prev: value}]
let _scanType  = null;
let _scanCount = 0;    // number of scans performed

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseValue(raw, type) {
  if (type === "bytes") return raw;           // already ArrayBuffer/hex string
  if (type.startsWith("float") || type === "double") return parseFloat(raw);
  return parseInt(raw, 10);
}

function readValue(ptr, type) {
  const td = TYPES[type];
  if (!td || !td.read) return null;
  try { return td.read(ptr); } catch (_) { return null; }
}

function cmpOk(cur, prev, target, filterType) {
  switch (filterType) {
    case "eq":        return cur == target;
    case "ne":        return cur != target;
    case "gt":        return cur > target;
    case "lt":        return cur < target;
    case "gte":       return cur >= target;
    case "lte":       return cur <= target;
    case "changed":   return cur != prev;
    case "unchanged": return cur == prev;
    default:          return cur == target;
  }
}

// Enumerate writable (or at least readable) memory regions, skip system libs
function* scanRegions() {
  for (const range of Process.enumerateRanges("r--")) {
    const path = range.file ? range.file.path : "";
    // Skip system libraries and non-app memory
    if (path.startsWith("/system") || path.startsWith("/apex") ||
        path.startsWith("/vendor") || path.startsWith("/data/dalvik-cache")) {
      continue;
    }
    yield range;
  }
}

// ── First scan ────────────────────────────────────────────────────────────────

function firstScan(rawValue, type) {
  const td = TYPES[type];
  if (!td) throw new Error(`Unknown type: ${type}`);

  _results  = [];
  _scanType = type;
  _scanCount = 1;

  const target = parseValue(rawValue, type);
  const size   = td.size;

  if (type === "bytes") {
    // Byte-array search — rawValue is hex string "DE AD BE EF"
    const pattern = rawValue.trim().replace(/\s+/g, " ");
    for (const range of scanRegions()) {
      try {
        const matches = Memory.scanSync(range.base, range.size, pattern);
        for (const m of matches) {
          if (_results.length >= MAX_RESULTS) break;
          _results.push({ addr: m.address, prev: pattern });
        }
      } catch (_) {}
      if (_results.length >= MAX_RESULTS) break;
    }
  } else {
    for (const range of scanRegions()) {
      const base  = range.base;
      const total = range.size - size + 1;
      for (let off = 0; off < total; off += size) {
        const ptr = base.add(off);
        const val = readValue(ptr, type);
        if (val === null) break;
        if (val == target) {
          _results.push({ addr: ptr, prev: val });
          if (_results.length >= MAX_RESULTS) break;
        }
      }
      if (_results.length >= MAX_RESULTS) break;
    }
  }

  return { count: _results.length, scanCount: _scanCount };
}

// ── Refinement scan ───────────────────────────────────────────────────────────

function filterScan(rawValue, filterType) {
  if (_results.length === 0) throw new Error("No previous scan. Run scan() first.");

  _scanCount++;
  const target = (filterType === "changed" || filterType === "unchanged")
    ? null
    : parseValue(rawValue, _scanType);

  const kept = [];
  for (const entry of _results) {
    const cur = readValue(entry.addr, _scanType);
    if (cur === null) continue;
    if (cmpOk(cur, entry.prev, target, filterType)) {
      kept.push({ addr: entry.addr, prev: cur });
    }
  }
  _results = kept;
  return { count: _results.length, scanCount: _scanCount };
}

// ── RPC ───────────────────────────────────────────────────────────────────────

rpc.exports = {
  scan(rawValue, type) {
    try {
      return firstScan(String(rawValue), type || "int32");
    } catch (e) {
      return { error: e.message };
    }
  },

  filter(rawValue, filterType) {
    try {
      return filterScan(String(rawValue), filterType || "eq");
    } catch (e) {
      return { error: e.message };
    }
  },

  results(max) {
    const limit = Math.min(max || 200, _results.length);
    return _results.slice(0, limit).map(e => ({
      addr:  e.addr.toString(),
      value: readValue(e.addr, _scanType),
    }));
  },

  reset() {
    _results   = [];
    _scanType  = null;
    _scanCount = 0;
    return { ok: true };
  },

  info() {
    return {
      scanCount: _scanCount,
      resultCount: _results.length,
      type: _scanType,
    };
  },
};
