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

// cc::DrawTextBlobOp / cc::DrawSlugOp layout (verified by disassembling the
// kDrawTextBlob case inlined into PaintOpWithFlags::RasterWithFlags in Brave
// 1.90.122-1):
//   +0x50: sk_sp<SkTextBlob> blob (or sk_sp<sktext::gpu::Slug> slug for kDrawSlug)
//   +0x78: SkScalar x   (float, layer-local — pre-CTM)
//   +0x7c: SkScalar y
const DRAW_TEXT_X_OFF = 0x78;
const DRAW_TEXT_Y_OFF = 0x7c;

// Phase 2: cc::DrawRectOp / DrawRRectOp / DrawIRectOp / DrawOvalOp all inherit
// PaintOpWithFlagsBaseInternal directly and put the geometry field as the
// first derived-class member. PaintOpWithFlags base is 0x50 bytes (PaintOp.type
// uint8 + 7B pad, then PaintFlags which is align-8 = CorePaintFlags{
// SkColor4f color_(16B), width_(4B), miter_limit_(4B), bitfields(4B), pad(4B) }
// then targeted_hdr_headroom_(4B), pad(4B), 5 sk_sp ptrs(40B) = 72B).
// Confirmed by disassembling the inlined kDrawRect case (jmps to SkCanvas::
// drawRect after `add $0x50,%r14`) and the out-of-line kDrawRRect/kDrawOval/
// kDrawIRect bodies (same pattern).
const DRAW_RECT_OFF  = 0x50;   // SkRect  (4 f32 ltrb) for DrawRect / DrawRRect.fRect / DrawOval.oval
const DRAW_IRECT_OFF = 0x50;   // SkIRect (4 s32 ltrb) for DrawIRect

// PaintFlags layout (verified by disassembling the kDrawRect inlined case —
// it loads `movups (%r15),%xmm0` from the flags arg, where r15 holds the
// dispatcher's rsi). CorePaintFlags.color_ is SkColor4f (4 f32 RGBA) at
// offset 0 of the flags pointer.
const FLAGS_COLOR_OFF = 0x00;

// Sentinel used by SkCanvas::drawRect hook (no PaintFlags pointer available).
const NULL_PTR = ptr(0);

// Phase 8: SkCanvas current-transform-matrix readout. SkCanvas has a private
// member `MCRec* fMCRec` pointing at the top of its matrix-clip stack;
// MCRec contains `SkM44 fMatrix` (column-major 16 f32). Verified in
// Brave 1.90.122-1 by disassembling SkCanvas::drawRect (0x3f71470) and
// SkCanvas::drawTextBlob (0x3f61330): both emit
//     mov 0x640(this), %rNN
//     add $0x18, %rNN
//     call SkM44::mapRect(this=&matrix, &rect)
// so fMCRec is at +0x640 and fMatrix is at MCRec+0x18.
// Defaults below match this build; signatures.json may override.
const SK_CANVAS_MCREC_OFF_DEFAULT = 0x640;
const MCREC_MATRIX_OFF_DEFAULT    = 0x18;

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
  // Renderer hosts Blink + cc recording (hb_shape_full lives here).
  // GPU process hosts SkiaRenderer/raster (cc::PaintOp dispatch arrays fire here).
  // We accept both; install() probes which offsets resolve and hooks accordingly.
  return cmdline.includes('--type=renderer') || cmdline.includes('--type=gpu-process');
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

  installPaintOpHooks(opts.offsets || {});
}

// Phase 6 (draw_text) + Phase 7 (draw_rect): hooks on the cc::PaintOp
// rasterization path, fired only in the GPU process.
//
// Three hook strategies in layered priority:
//
//   A. PaintOpWithFlags::RasterWithFlags member-function dispatcher
//      (`offs.paint_op_with_flags_RasterWithFlags`). cc::PaintOpBuffer::
//      Playback dispatches every flags-bearing op through this — in
//      principle. clang LTO inlines all simple geometry cases into
//      Playback itself in this build, so only kDrawTextBlob / kDrawSlug
//      reliably reach this entry. Captures text positions for Phase 6.
//
//   B. Per-op static T::RasterWithFlags. Each is the resolved target of
//      the corresponding `g_raster_with_flags_functions[k]` slot. Fires
//      for the occasional op that escapes inlining. Has the PaintFlags
//      pointer in rsi, so emits geometry AND colour.
//
//   C. SkCanvas::drawRect — the catch-all. Most filled rects in this
//      build come from cc::PaintOps that got LTO-inlined past the per-op
//      RasterWithFlags entries; they still land in Skia, so hooking
//      drawRect catches them. Colour decode of SkPaint is deferred,
//      geometry only.
//
// All three feed the same `draw_rect` JSONL records and share a 16K LRU
// keyed by kind + quantised geometry + colour.
function installPaintOpHooks(offs) {
  const pid = Process.id;
  const mod = findBraveModule();
  if (!mod) return;
  const dispOffHex = offs.paint_op_with_flags_RasterWithFlags;
  if (!dispOffHex) {
    log({ type: 'warn', msg: 'no paint_op_with_flags_RasterWithFlags offset configured' });
    return;
  }
  const dispOff = parseInt(dispOffHex, 16);
  if (!Number.isFinite(dispOff) || dispOff <= 0) {
    log({ type: 'error', msg: `bad paint_op_with_flags_RasterWithFlags offset: ${dispOffHex}` });
    return;
  }
  const dispAddr = mod.base.add(dispOff);
  const kDrawIRect    = (offs.paint_op_kDrawIRect    | 0) || 12;
  const kDrawOval     = (offs.paint_op_kDrawOval     | 0) || 15;
  const kDrawRect     = (offs.paint_op_kDrawRect     | 0) || 18;
  const kDrawRRect    = (offs.paint_op_kDrawRRect    | 0) || 19;
  const kDrawSlug     = (offs.paint_op_kDrawSlug     | 0) || 22;
  const kDrawTextBlob = (offs.paint_op_kDrawTextBlob | 0) || 23;

  // Phase 8: configurable CTM read path (defaults pinned to Brave 1.90.122-1).
  const skCanvasMCRecOff = parseInt(offs.sk_canvas_mcrec_offset, 16);
  const mcrecMatrixOff   = parseInt(offs.mcrec_matrix_offset,    16);
  const CTM_MCREC_OFF  = Number.isFinite(skCanvasMCRecOff) && skCanvasMCRecOff > 0
    ? skCanvasMCRecOff : SK_CANVAS_MCREC_OFF_DEFAULT;
  const CTM_MATRIX_OFF = Number.isFinite(mcrecMatrixOff) && mcrecMatrixOff > 0
    ? mcrecMatrixOff : MCREC_MATRIX_OFF_DEFAULT;

  // Read the current 4x4 transform matrix from an SkCanvas*.
  // SkM44 is column-major: fMat[c*4 + r] — element (r,c) of the matrix.
  // For a 2D affine the only relevant entries are
  //   m00=fMat[0]  m01=fMat[4]  m03=fMat[12]    (x-scale, xy-shear, x-translate)
  //   m10=fMat[1]  m11=fMat[5]  m13=fMat[13]    (yx-shear, y-scale, y-translate)
  // We expose those six numbers as `ctm` (a 6-element 2D-affine row) so the
  // host can map any layer-local (x,y) → screen (sx,sy) without knowing
  // SkM44's storage convention.
  function readCTM(canvas) {
    if (canvas.isNull()) return null;
    let mcrec;
    try { mcrec = canvas.add(CTM_MCREC_OFF).readPointer(); }
    catch (e) { return null; }
    if (mcrec.isNull()) return null;
    let m;
    try { m = mcrec.add(CTM_MATRIX_OFF).readByteArray(64); }
    catch (e) { return null; }
    const v = new Float32Array(m);
    // [m00, m01, m03, m10, m11, m13]  (in 2D row-major affine order)
    return [v[0], v[4], v[12], v[1], v[5], v[13]];
  }

  function applyCTM(ctm, x, y) {
    if (!ctm) return null;
    const sx = ctm[0] * x + ctm[1] * y + ctm[2];
    const sy = ctm[3] * x + ctm[4] * y + ctm[5];
    return [sx, sy];
  }

  // Paint-op events fire orders of magnitude more often than text shapings
  // (every box decoration, focus ring, scrollbar segment). Give them their
  // own much-larger LRU keyed on kind + quantised geometry + packed color
  // so the host doesn't drown.
  const rectDedupe = makeDeduper(LRU_CAP * 4);

  function rectKey(kind, l, t, r, b, c) {
    // Quantise to 1px and pack color so wiggle from CTM rounding doesn't
    // explode the dedupe cache.
    return kind + '|' +
      (l|0) + ',' + (t|0) + ',' + (r|0) + ',' + (b|0) + '|' + c;
  }

  function emitRect(kind, op, flagsPtr, canvas, l, t, r, b) {
    let color = '';
    if (!flagsPtr.isNull()) {
      try {
        // SkColor4f RGBA (4 little-endian floats); convert to 0..255 hex
        // string so the post-processor doesn't have to know the encoding.
        const fr = flagsPtr.add(FLAGS_COLOR_OFF + 0x0).readFloat();
        const fg = flagsPtr.add(FLAGS_COLOR_OFF + 0x4).readFloat();
        const fb = flagsPtr.add(FLAGS_COLOR_OFF + 0x8).readFloat();
        const fa = flagsPtr.add(FLAGS_COLOR_OFF + 0xc).readFloat();
        const clamp = v => Math.max(0, Math.min(255, Math.round(v * 255)));
        color = '#' +
          clamp(fr).toString(16).padStart(2, '0') +
          clamp(fg).toString(16).padStart(2, '0') +
          clamp(fb).toString(16).padStart(2, '0') +
          clamp(fa).toString(16).padStart(2, '0');
      } catch (e) { /* fall through colorless */ }
    }
    // Phase 8: dedupe key uses absolute (post-CTM) bounds so identical content
    // painted at different scroll offsets shows up as distinct records.
    const ctm = canvas ? readCTM(canvas) : null;
    const tl = applyCTM(ctm, l, t);
    const br = applyCTM(ctm, r, b);
    const keyL = tl ? tl[0] : l;
    const keyT = tl ? tl[1] : t;
    const keyR = br ? br[0] : r;
    const keyB = br ? br[1] : b;
    if (!rectDedupe(rectKey(kind, keyL, keyT, keyR, keyB, color))) return;
    const rec = { type: 'draw_rect', kind, pid,
                  left: l, top: t, right: r, bottom: b,
                  color, op: op.toString() };
    if (tl && br) {
      rec.sleft = tl[0]; rec.stop = tl[1];
      rec.sright = br[0]; rec.sbottom = br[1];
      rec.ctm = ctm;
    }
    log(rec);
  }

  try {
    // Hook A: the PaintOpWithFlags::RasterWithFlags member-function dispatcher
    // (used by cc::PaintOpBuffer::Playback). Text-bearing ops (kDrawTextBlob,
    // kDrawSlug) reliably flow through this path; in OOPR-Skia builds the
    // simpler geometry ops largely bypass it for the per-op static fast path
    // hooked below.
    Interceptor.attach(dispAddr, {
      onEnter(args) {
        // PaintOpWithFlags::RasterWithFlags is a NON-STATIC member function:
        //   void RasterWithFlags(SkCanvas* canvas, const PaintFlags* flags,
        //                        const PlaybackParams& params) const;
        // SysV AMD64: rdi=this=op, rsi=canvas, rdx=flags, rcx=params.
        // (The static per-op T::RasterWithFlags has a different order:
        //  (op, flags, canvas, params) — see hooks B-E below.)
        const op = args[0];
        const canvas = args[1];
        if (op.isNull()) return;
        let t;
        try { t = op.readU8(); } catch (e) { return; }
        if (t === kDrawTextBlob) {
          let x, y;
          try {
            x = op.add(DRAW_TEXT_X_OFF).readFloat();
            y = op.add(DRAW_TEXT_Y_OFF).readFloat();
          } catch (e) { return; }
          // Phase 8: read CTM from SkCanvas (args[1]); apply to op-local x,y.
          const ctm = readCTM(canvas);
          const s = applyCTM(ctm, x, y);
          const rec = { type: 'draw_text', kind: 'DrawTextBlob', pid,
                        x, y, op: op.toString() };
          if (s) { rec.sx = s[0]; rec.sy = s[1]; rec.ctm = ctm; }
          log(rec);
          return;
        }
        if (t === kDrawSlug) {
          // Slug carries its own per-glyph positions, but the CTM lets
          // downstream tooling place the slug origin if it ever learns to
          // decode sktext::gpu::Slug internals.
          const ctm = readCTM(canvas);
          const rec = { type: 'draw_text', kind: 'DrawSlug', pid,
                        op: op.toString() };
          if (ctm) rec.ctm = ctm;
          log(rec);
          return;
        }
      }
    });
    log({ type: 'hooked', name: 'PaintOpWithFlags::RasterWithFlags', address: dispAddr.toString() });
  } catch (e) {
    log({ type: 'error', msg: `dispatcher hook failed: ${e.message}` });
  }

  // Hooks B-E: per-op static T::RasterWithFlags(op, flags, canvas, params).
  // These are the entries actually wired into g_raster_with_flags_functions[k];
  // the OOPR-Skia replay loop in cc::PaintOpBuffer dispatches via this array
  // for non-text ops without going through the member-function dispatcher.
  // SysV: rdi=op, rsi=flags, rdx=canvas, rcx=params.
  function hookPerOp(name, kind, offsetHex, isIRect) {
    if (!offsetHex) { log({ type: 'warn', msg: `no offset for ${name}` }); return; }
    const off = parseInt(offsetHex, 16);
    if (!Number.isFinite(off) || off <= 0) {
      log({ type: 'error', msg: `bad offset for ${name}: ${offsetHex}` });
      return;
    }
    const addr = mod.base.add(off);
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          const op = args[0];
          const flagsPtr = args[1];
          const canvas = args[2];
          if (op.isNull()) return;
          let l, top, r, b;
          try {
            const base = op.add(DRAW_RECT_OFF);
            if (isIRect) {
              l   = base.add(0x0).readS32();
              top = base.add(0x4).readS32();
              r   = base.add(0x8).readS32();
              b   = base.add(0xc).readS32();
            } else {
              l   = base.add(0x0).readFloat();
              top = base.add(0x4).readFloat();
              r   = base.add(0x8).readFloat();
              b   = base.add(0xc).readFloat();
            }
          } catch (e) { return; }
          emitRect(kind, op, flagsPtr, canvas, l, top, r, b);
        }
      });
      log({ type: 'hooked', name, address: addr.toString() });
    } catch (e) {
      log({ type: 'error', msg: `${name} hook failed: ${e.message}` });
    }
  }

  // The per-op function VAs aren't in offsets:{} — they live under
  // known_anchors in signatures.json. run.py passes the whole signatures.json
  // through as opts.offsets currently, so we read from there directly via
  // opts to avoid forcing a schema migration. For Brave 1.90.122-1:
  //   DrawRect  -> 0x595a250  (DrawOp_rect lambda slot)
  //   DrawRRect -> 0x3deabc0
  //   DrawIRect -> 0x3df0d20
  //   DrawOval  -> 0x3de6020
  // Sources: g_raster_with_flags_functions thunk-slot relocations at
  // 11a5edb0 / b8 / d80 / d98 (see signatures.json:known_anchors).
  hookPerOp('DrawRectOp::RasterWithFlags',  'DrawRect',  offs.draw_rect_op_RasterWithFlags  || '0x595a250', false);
  hookPerOp('DrawRRectOp::RasterWithFlags', 'DrawRRect', offs.draw_rrect_op_RasterWithFlags || '0x3deabc0', false);
  hookPerOp('DrawIRectOp::RasterWithFlags', 'DrawIRect', offs.draw_irect_op_RasterWithFlags || '0x3df0d20', true);
  hookPerOp('DrawOvalOp::RasterWithFlags',  'DrawOval',  offs.draw_oval_op_RasterWithFlags  || '0x3de6020', false);

  // Hook F: SkCanvas::drawRect. In Brave 1.90.122-1's OOPR-Skia gpu-process,
  // the per-op static T::RasterWithFlags functions for kDrawRect/RRect/IRect/
  // Oval almost never fire — clang LTO inlines them straight into
  // cc::PaintOpBuffer::Playback, which is reached only by the single tail
  // call at 0x3f6b404. The geometry still lands in Skia eventually, via
  // SkCanvas::drawRect (and friends). Hooking it captures every filled rect
  // regardless of the cc-side fast-path the op took. Downside: this also
  // catches rects from Chromium's own compositor decoration (selection
  // highlights, focus rings) and any third-party Skia user — there's no
  // clean way to tell those apart from PaintOp-originated rects without
  // walking the stack. SkPaint colour decode is non-trivial and version-
  // sensitive, so we punt colour for this path; geometry alone is enough
  // for the Phase 2 ASCII-render scaffold.
  if (offs.SkCanvas_drawRect) {
    const skRectOff = parseInt(offs.SkCanvas_drawRect, 16);
    if (Number.isFinite(skRectOff) && skRectOff > 0) {
      const skRectAddr = mod.base.add(skRectOff);
      try {
        Interceptor.attach(skRectAddr, {
          onEnter(args) {
            // rdi=this(SkCanvas*), rsi=&rect, rdx=&paint
            const canvas = args[0];
            const rectPtr = args[1];
            if (rectPtr.isNull()) return;
            let l, top, r, b;
            try {
              l   = rectPtr.add(0x0).readFloat();
              top = rectPtr.add(0x4).readFloat();
              r   = rectPtr.add(0x8).readFloat();
              b   = rectPtr.add(0xc).readFloat();
            } catch (e) { return; }
            // Colour deferred (SkPaint layout is version-fragile); emitRect
            // skips colour decoding when the flags pointer is NULL.
            emitRect('SkRect', NULL_PTR, NULL_PTR, canvas, l, top, r, b);
          }
        });
        log({ type: 'hooked', name: 'SkCanvas::drawRect', address: skRectAddr.toString() });
      } catch (e) {
        log({ type: 'error', msg: `SkCanvas::drawRect hook failed: ${e.message}` });
      }
    }
  }
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
