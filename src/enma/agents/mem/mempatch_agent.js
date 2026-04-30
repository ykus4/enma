"use strict";
/**
 * mempatch_agent — memory write, NOP, and value freeze.
 *
 * RPC exports:
 *   write(addr, type, value)   — write a typed value to address
 *   writeBytes(addr, hex)      — write raw bytes (hex string "DE AD BE EF")
 *   nop(addr, count)           — overwrite with ARM64/ARM/x86 NOPs
 *   freeze(addr, type, value)  — repeatedly write value every <interval> ms
 *   unfreeze(addr)             — stop freezing an address
 *   listFrozen()               — list currently frozen addresses
 *   read(addr, type, count)    — read and return value(s) at address
 */

const TYPES = {
  int8:   { size: 1, read: (p) => p.readS8(),      write: (p, v) => p.writeS8(Number(v))      },
  int16:  { size: 2, read: (p) => p.readS16(),     write: (p, v) => p.writeS16(Number(v))     },
  int32:  { size: 4, read: (p) => p.readS32(),     write: (p, v) => p.writeS32(Number(v))     },
  int64:  { size: 8, read: (p) => p.readS64(),     write: (p, v) => p.writeS64(v)             },
  uint8:  { size: 1, read: (p) => p.readU8(),      write: (p, v) => p.writeU8(Number(v))      },
  uint16: { size: 2, read: (p) => p.readU16(),     write: (p, v) => p.writeU16(Number(v))     },
  uint32: { size: 4, read: (p) => p.readU32(),     write: (p, v) => p.writeU32(Number(v))     },
  uint64: { size: 8, read: (p) => p.readU64(),     write: (p, v) => p.writeU64(v)             },
  float:  { size: 4, read: (p) => p.readFloat(),   write: (p, v) => p.writeFloat(Number(v))   },
  double: { size: 8, read: (p) => p.readDouble(),  write: (p, v) => p.writeDouble(Number(v))  },
};

// NOP bytes per architecture
function nopByte() {
  const arch = Process.arch;
  if (arch === "arm64") return [0x1f, 0x20, 0x03, 0xd5];  // NOP (4 bytes)
  if (arch === "arm")   return [0x00, 0x00, 0xa0, 0xe3];  // MOV R0,R0
  return [0x90];  // x86/x86_64
}

// ── Freeze registry ──────────────────────────────────────────────────────────

const _frozen = new Map();  // addr string → {intervalId, type, value}

function freezeAddr(addrStr, type, value, intervalMs) {
  if (_frozen.has(addrStr)) clearInterval(_frozen.get(addrStr).intervalId);
  const ptr = ptr(addrStr);
  const td  = TYPES[type];
  if (!td) throw new Error(`Unknown type: ${type}`);

  const id = setInterval(() => {
    try {
      Memory.protect(ptr, td.size, "rw-");
      td.write(ptr, value);
    } catch (_) {}
  }, intervalMs || 100);

  _frozen.set(addrStr, { intervalId: id, type, value: String(value) });
}

// ── RPC ───────────────────────────────────────────────────────────────────────

rpc.exports = {
  write(addrStr, type, value) {
    try {
      const p  = ptr(addrStr);
      const td = TYPES[type];
      if (!td) return { error: `Unknown type: ${type}` };
      Memory.protect(p, td.size, "rw-");
      td.write(p, value);
      return { ok: true, addr: addrStr, type, value: String(value) };
    } catch (e) {
      return { error: e.message };
    }
  },

  writeBytes(addrStr, hex) {
    try {
      const bytes = hex.trim().split(/\s+/).map(b => parseInt(b, 16));
      const p = ptr(addrStr);
      Memory.protect(p, bytes.length, "rw-");
      p.writeByteArray(bytes);
      return { ok: true, addr: addrStr, bytes: bytes.length };
    } catch (e) {
      return { error: e.message };
    }
  },

  nop(addrStr, count) {
    try {
      const nopSeq  = nopByte();
      const n       = count || 1;
      const total   = n * nopSeq.length;
      const p       = ptr(addrStr);
      Memory.protect(p, total, "rw-");
      const buf = [];
      for (let i = 0; i < n; i++) buf.push(...nopSeq);
      p.writeByteArray(buf);
      return { ok: true, addr: addrStr, bytesWritten: total, arch: Process.arch };
    } catch (e) {
      return { error: e.message };
    }
  },

  freeze(addrStr, type, value, intervalMs) {
    try {
      freezeAddr(addrStr, type, value, intervalMs);
      return { ok: true, addr: addrStr, type, value: String(value) };
    } catch (e) {
      return { error: e.message };
    }
  },

  unfreeze(addrStr) {
    const entry = _frozen.get(addrStr);
    if (!entry) return { error: "Address not frozen" };
    clearInterval(entry.intervalId);
    _frozen.delete(addrStr);
    return { ok: true, addr: addrStr };
  },

  listFrozen() {
    const list = [];
    for (const [addr, entry] of _frozen.entries()) {
      list.push({ addr, type: entry.type, value: entry.value });
    }
    return list;
  },

  read(addrStr, type, count) {
    try {
      const p  = ptr(addrStr);
      const td = TYPES[type];
      if (!td) return { error: `Unknown type: ${type}` };
      const n = count || 1;
      if (n === 1) {
        return { addr: addrStr, type, value: td.read(p) };
      }
      const vals = [];
      for (let i = 0; i < n; i++) vals.push(td.read(p.add(i * td.size)));
      return { addr: addrStr, type, values: vals };
    } catch (e) {
      return { error: e.message };
    }
  },
};
