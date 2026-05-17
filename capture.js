// brave-frida-capture: hook hb_shape_full in renderer processes and read
// the input codepoints out of the buffer. Catches every text path
// (latin1/utf16/utf32/hb_buffer_add) since they all funnel into hb_shape_full.
//
// Loaded into every process Frida attaches to; early-exits in non-renderer
// processes so we don't waste cycles on the browser/utility/gpu processes.
//
// Wire-up: run.py sends one message of shape
//   { type: "signatures", payload: { offsets: { hb_shape_full: "0x...", ... } } }
// after attach.

'use strict';

const MAX_TEXT_LEN_UTF16  = 1 << 20;   // sanity cap on length arg (1M code units)
const LRU_CAP             = 4096;       // per-process dedupe window
const MODULE_NAMES        = ['brave', '/opt/brave-bin/brave'];
const BRAVE_PATH_HINT     = '/brave-bin/brave';

let offsets = null;
let isRendererProc = false;

function log(payload) {
  send(payload);
}

function readCmdline() {
  try {
    const f = new File('/proc/self/cmdline', 'rb');
    const bytes = f.readBytes(4096);
    f.close();
    return Array.from(new Uint8Array(bytes))
      .map(b => b === 0 ? ' ' : String.fromCharCode(b))
      .join('');
  } catch (e) {
    return '';
  }
}

function isRenderer(cmdline) {
  return cmdline.includes('--type=renderer');
}

function findBraveModule() {
  for (const name of MODULE_NAMES) {
    const m = Process.findModuleByName(name);
    if (!m) continue;
    if (m.path && m.path.indexOf(BRAVE_PATH_HINT) !== -1) return m;
  }
  return null;
}

function installHook(name, offsetHex, onEnter) {
  if (!offsetHex) {
    log({ type: 'warn', msg: `no offset configured for ${name}` });
    return;
  }
  const mod = findBraveModule();
  if (!mod) {
    log({ type: 'error', msg: 'brave module not found in process' });
    return;
  }
  const off = parseInt(offsetHex, 16);
  if (!Number.isFinite(off) || off <= 0) {
    log({ type: 'error', msg: `bad offset for ${name}: ${offsetHex}` });
    return;
  }
  const target = mod.base.add(off);
  try {
    Interceptor.attach(target, { onEnter });
    log({ type: 'hooked', name, address: target.toString(), module: mod.name, base: mod.base.toString() });
  } catch (e) {
    log({ type: 'error', msg: `Interceptor.attach failed for ${name}: ${e.message}` });
  }
}

function makeDeduper(cap) {
  const seen = new Map();
  return s => {
    if (seen.has(s)) return false;
    if (seen.size >= cap) {
      const oldest = seen.keys().next().value;
      seen.delete(oldest);
    }
    seen.set(s, 1);
    return true;
  };
}

function install(opts) {
  offsets = opts.offsets || {};
  const pid = Process.id;
  const dedupe = makeDeduper(LRU_CAP);

  // hb_buffer_t layout in chromium-vendored HarfBuzz 13.1.0 (x86_64):
  //   +0x60: unsigned int len                  (verified — hb_shape_full reads it, bails if 0)
  //   +0x70: hb_glyph_info_t *info             (initial guess; first-shape dump confirms)
  // hb_glyph_info_t stride = 20 bytes; .codepoint (uint32) at +0x00 holds
  // the original Unicode codepoint until shaping replaces it with a glyph ID.
  const BUF_LEN_OFF  = 0x60;
  const BUF_INFO_OFF = 0x70;
  const INFO_STRIDE  = 20;
  let dumpedOnce = false;

  installHook('hb_shape_full', offsets.hb_shape_full, function (args) {
    const buffer = args[1];
    if (buffer.isNull()) return;
    let len, infoPtr;
    try {
      len     = buffer.add(BUF_LEN_OFF).readU32();
      infoPtr = buffer.add(BUF_INFO_OFF).readPointer();
    } catch (e) { return; }
    if (len === 0 || len > MAX_TEXT_LEN_UTF16) return;
    if (infoPtr.isNull()) return;

    if (!dumpedOnce) {
      dumpedOnce = true;
      try {
        const bytes = buffer.readByteArray(0x90);
        const firstInfo = infoPtr.readByteArray(40);
        log({ type: 'dump', pid, len, infoPtr: infoPtr.toString(),
              buffer_hex: Array.from(new Uint8Array(bytes))
                .map(b => b.toString(16).padStart(2, '0')).join(' '),
              info0_hex: Array.from(new Uint8Array(firstInfo))
                .map(b => b.toString(16).padStart(2, '0')).join(' ') });
      } catch (e) {}
    }

    const codepoints = [];
    try {
      for (let i = 0; i < len; i++) {
        codepoints.push(infoPtr.add(i * INFO_STRIDE).readU32());
      }
    } catch (e) { return; }

    let valid = 0;
    for (const cp of codepoints) if (cp > 0 && cp <= 0x10ffff) valid++;
    if (valid < codepoints.length / 2) return;

    let s = '';
    for (const cp of codepoints) {
      if (cp >= 0 && cp <= 0x10ffff) s += String.fromCodePoint(cp);
    }
    const trimmed = s.replace(/^[\s ]+|[\s ]+$/g, '');
    if (!trimmed) return;
    if (!dedupe(trimmed)) return;
    log({ type: 'text', pid, len: trimmed.length, text: trimmed });
  });
}

const cmdline = readCmdline();
if (!isRenderer(cmdline)) {
  isRendererProc = false;
  log({ type: 'skip', pid: Process.id, reason: 'not a renderer', cmdline: cmdline.trim().slice(0, 200) });
} else {
  isRendererProc = true;
  log({ type: 'ready', pid: Process.id });
}

recv('signatures', m => {
  if (!isRendererProc) return;
  install(m.payload);
});
