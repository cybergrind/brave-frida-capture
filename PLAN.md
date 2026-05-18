# PLAN — as-built design + history

Companion to [CLAUDE.md](./CLAUDE.md) (which covers the project goal and
constraints) and [FINDING_OFFSETS.md](./FINDING_OFFSETS.md) (the
authoritative refresh workflow). This file is the design record: what we
built, why, and the dead ends that informed the shape.

## Architecture (as built)

```
   ┌──────────────────────────────────────────────────────────────┐
   │  run.py (host)                                               │
   │                                                              │
   │   1. ensure ~/.config/BraveSoftware/brave-frida/             │
   │   2. read ~/.config/brave-flags.conf for Wayland/GPU flags   │
   │   3. subprocess.Popen brave (NOT frida.spawn — see below)    │
   │   4. background thread polls /proc for new PIDs whose        │
   │      cmdline has BOTH our --user-data-dir AND --type=renderer│
   │   5. for each match: frida.attach + inject capture.js        │
   │   6. print each {type:"text"} message to stdout              │
   └──────────────────────────────────────────────────────────────┘
                                │
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  brave renderer process                                      │
   │                                                              │
   │   capture.js gates on /proc/self/cmdline (--type=renderer).  │
   │                                                              │
   │   base = Module.findBaseAddress("brave")  // path-filtered   │
   │   Interceptor.attach(base + sig.hb_shape_full, {             │
   │     onEnter(args) {                                          │
   │       const buf  = args[1];                                  │
   │       const len  = buf.add(0x60).readU32();                  │
   │       const info = buf.add(0x70).readPointer();              │
   │       // each hb_glyph_info_t is 20 B; .codepoint at +0      │
   │       const s = readCodepoints(info, len);                   │
   │       if (dedupe.add(s)) send({type:"text", pid, text:s});   │
   │     }                                                        │
   │   });                                                        │
   └──────────────────────────────────────────────────────────────┘
```

## Why these specific choices

### Hook target: `hb_shape_full`, not `hb_buffer_add_utf16`

The obvious target is `hb_buffer_add_utf16` — Blink passes the source text
straight into it. We tried that first and **only captured Chromium font-probe
text** (`Cwm fjordbank gly[phs] 😃`). Diagnosing:

Blink's shape paths in `harfbuzz_shaper.cc` (`HarfBuzzShaper::GetGlyphData`,
~line 1175) and `case_mapping_harfbuzz_buffer_filler.cc` (~line 31) branch
on the string's storage width:

```cpp
if (text.Is8Bit()) {
  hb_buffer_add_latin1(buffer, span.data(), span.size(), ...);
} else {
  hb_buffer_add_utf16(buffer, span.data(), span.size(), ...);
}
```

ASCII page text takes the `_latin1` path, which our hook missed. The probe
strings showed because they contain non-Latin-1 codepoints (Welsh
pangram + emoji) → forced into `_utf16`.

**Fix:** hook `hb_shape_full` — every text run, regardless of which
`hb_buffer_add_*` variant filled the buffer, passes through it. At entry,
`buffer->info[i].codepoint` holds the input Unicode codepoint (replaced
with a glyph ID later in the same call), so we read the buffer directly.

Verified against the Wikipedia HarfBuzz article: 482 captured lines, all
matching visible page content — infobox values (`14.2.0`), sidebar links,
body paragraphs, citation entries.

### Launch model: subprocess, not `frida.spawn` + child gating

The Frida-idiomatic approach is `frida.spawn(brave)` +
`session.enable_child_gating()` to catch every child process Brave forks.
We tried that. **Brave's startup stalled** — gpu / utility / broker /
renderer processes never came up; only zygote + crashpad-handler appeared.
Chromium's zygote uses a fork/clone variant that Frida's gating doesn't
handle cleanly, and holding the parent under Frida's gate makes the bigger
problem visible.

**Fix:** launch Brave as a plain `subprocess.Popen` (no Frida hold), and
use Frida only to *attach* to renderer PIDs as they appear in `/proc`.
The polling thread filters on the spawned process's `--user-data-dir=` so
we don't attach to the user's other Brave instance.

Side benefit: we can disambiguate which Brave we're driving by profile,
not by PID tree.

### Read `~/.config/brave-flags.conf`

The user's Wayland desktop needs `--ozone-platform=wayland` for Brave to
create a window at all; the system `/usr/bin/brave` shell wrapper passes
flags from `~/.config/brave-flags.conf`. We bypass that wrapper by going
straight to `/opt/brave-bin/brave`, so `run.py` reads the same conf inline
(splitting on lines, skipping comments and blanks).

### Persistent profile (not throwaway)

`~/.config/BraveSoftware/brave-frida/` is reused across runs. Originally
intended for cookies/logins persistence; in practice it also means Brave
restores session tabs, which can mislead naive testing (we initially saw
captured text from a restored Yandex captcha tab, not the URL we passed).
Use `--new-window <url>` when verifying to force a focused window with
fresh content.

## Phases

### Phase 1 — Find offsets in `/opt/brave-bin/brave` — DONE

Initial pattern-scan approach (comparing system libharfbuzz 14.2.0 bytes to
brave's vendored 13.1.0) failed: clang vs gcc prologues differ, and
`hb_buffer_t` field offsets shifted between HarfBuzz major versions, so
"prologue + read +0x4 + read +0x20" matched zero functions.

Replaced with an **MCP-driven xref chain**, which became the workflow
documented in [FINDING_OFFSETS.md](./FINDING_OFFSETS.md):

1. `HB_SHAPER_LIST` string in `.rodata` → real VA `0x1f22292`.
2. Only RIP-relative LEA xref → inside `hb_shapers_lazy_loader_t::create`
   (not `hb_options_init` — that function was removed from HarfBuzz long
   ago) at real VA `0x69df290`.
3. `mcp__binassist__xrefs` for callers of the lazy loader → two HarfBuzz
   internals. The one with a `mov 0x60(%rsi),%eax; test;je` early-out AND
   subsequent `movw $0, 0xd0(%rsi)` + `movl $0, 0xd8(%rsi)` (the `enter()`
   scratch-state zeroing) is `hb_shape_full` — real VA `0x44c9070`.
4. Sanity-anchor `hb_buffer_add_utf16` reached by walking from a Blink
   caller of `hb_shape_full` and matching the `+0x4` writable check + the
   text_length/item_length sentinel comparisons → real VA `0x44bec70`.

Quirks recorded along the way:

- **Binja MCP returns addresses with a `+0x400000` skew** for the current
  database (binary's preferred image base). Not universal — measure per
  build. Documented in FINDING_OFFSETS.md.
- **Chromium uses `-fcf-protection=none`** — no `endbr64` bytes in
  `.text`. Don't try to use endbr as a function-start anchor.

### Phase 2 — `run.py` launcher — DONE

- Brave path overridable via `--brave`; default `/opt/brave-bin/brave`.
- Profile dir `~/.config/BraveSoftware/brave-frida/`, created if missing,
  preserved across runs.
- Spawn argv (in order): `<brave>`, flags from `~/.config/brave-flags.conf`,
  `--no-sandbox`, `--user-data-dir=<profile>`, `--no-first-run`,
  `--no-default-browser-check`,
  `--disable-features=RendererCodeIntegrity`, then any user args after `--`.
- `subprocess.Popen` with stdout/stderr discarded.
- Background polling thread that scans `/proc/*/cmdline` once per second,
  attaches Frida to any new PID containing both `--user-data-dir=<profile>`
  and `--type=renderer`.
- Invocation: `uv run python run.py` (env declared in `pyproject.toml`).

### Phase 3 — `capture.js` Frida agent — DONE

- Early-exits in non-renderer processes (`/proc/self/cmdline` check for
  `--type=renderer`).
- Module lookup uses `BRAVE_PATH_HINT = '/brave-bin/brave'` to filter out
  same-basename non-brave modules (e.g. crashpad_handler if it happens to
  share a name).
- Interceptor at `module_base + offsets.hb_shape_full`.
- Reads `len` at `+0x60`, `info` ptr at `+0x70`, iterates 20-byte
  `hb_glyph_info_t` records, picks codepoint at `+0` of each, validates
  in `[0, 0x10ffff]`.
- Per-process LRU dedupe of size 4096; whitespace-trimmed strings.
- Sends `{type:"text", pid, text, len}` back to the host.

### Phase 4 — Documentation — DONE

- `README.md` — user-facing run instructions, known limits.
- `FINDING_OFFSETS.md` — refresh workflow for new Brave builds; pressure-tested by three reviewer subagents (defects found: misnamed anchor function, non-universal Binja skew, wrong field-offset narrative, stale fallback advice — all corrected).
- This file — design + history.
- `CLAUDE.md` — orientation for future agents.

### Phase 5 — End-to-end verification — DONE

Wikipedia HarfBuzz article via `uv run python run.py -- --new-window
https://en.wikipedia.org/wiki/HarfBuzz` produced 482 unique captured
lines, all matching visible page content. Diagnostic buffer dump
confirmed `len@+0x60` and `info@+0x70` offsets; `info[0].codepoint =
0x50 = 'P'` matched the first char of "Please confirm that you and not a
robot…" from an earlier capture.

### Phase 6 — Screen-position capture (`draw_text` events) — DONE

Adds layer-local `(x, y)` per text run by hooking the cc::PaintOp
rasterizer dispatch. Output stream now interleaves two record kinds:

- `{type:"text", text:...}` — Unicode codepoints at shape time (Phase 3, unchanged).
- `{type:"draw_text", kind:"DrawTextBlob", x, y, op}` — layer-local pixel position at raster time.

#### Hook target & design

The recording side (`push<DrawTextBlobOp>` in Blink) is templated /
inlined and offers no hookable surface. The rasterizing side
(`cc::PaintOp::Raster` / `cc::PaintOpWithFlags::RasterWithFlags`) is a
real function and is reached by every text-blob op on its way to
`SkCanvas::drawTextBlob`. We hook
`PaintOpWithFlags::RasterWithFlags` (real VA `0x3f59ad0`) once per
process and filter in JS on `op->type == 23` (kDrawTextBlob).

`op->x` and `op->y` are read from offsets `+0x78` and `+0x7c` of the
PaintOp instance — verified by disassembling the inlined kDrawTextBlob
case (`movss 0x78(%r14), %xmm0; movss 0x7c(%r14), %xmm1;
call <SkCanvas::drawTextBlob>`).

#### Where Phase 6 fires (and where it doesn't)

`PaintOpWithFlags::RasterWithFlags` is invoked **only by the
gpu-process** during the SkiaRenderer raster pass; renderer
processes never execute it (they record PaintOps and ship them via
IPC). So `run.py` and `capture.js` were extended to also attach to
`--type=gpu-process` (in addition to `--type=renderer`), and
`installDrawTextHooks` no-ops in any process where the dispatcher
isn't present on the hot path.

This split is deliberate: the renderer process keeps its hb_shape_full
hook (text content, no position); the gpu-process gets the draw_text
hook (position, no readable text). Correlating the two is left to the
consumer.

#### Compiler-LTO quirk that bit us

clang LTO inlined the three hot cases of `g_raster_with_flags_functions`
(kDrawRect=18, kDrawPath=16, kDrawTextBlob=23) directly into the
dispatcher's body, dispatching them with explicit `cmp $imm, %ecx; je
<inline_case>` chains *before* falling through to the indirect
`jmp *%rax` over the array. The array's slot 23 still exists as an
out-of-line copy (real VA `0x6174c60`) and slot 22 (DrawSlug) similarly
(thunk at `0xbbfcd70` → body at `0xbbfa0a0`), but they're unreachable
on the fast path. Initial implementation hooked those out-of-line
copies and silently never fired. Fix: hook the dispatcher itself and
filter by type in JS.

#### kDrawSlug

DrawSlugOp doesn't carry x/y — the slug carries its own per-glyph
positions. We still emit a `draw_text` record with `kind:"DrawSlug"`
and the op pointer, but no coordinates. In the 1.90.122-1 Wikipedia
test slug-path records didn't appear (Skia/Blink-controlled
optimization that prefers DrawTextBlobOp here); the hook is
non-pessimising for builds where the slug path does fire.

#### CTM is deferred (resolved in Phase 8)

The captured `(x, y)` was originally **layer-local** — pre-CTM, in the
PaintRecord's own coordinate space. Phase 8 adds the SkCanvas CTM read
and emits `(sx, sy)` alongside `(x, y)` on every record; see
[Phase 8](#phase-8--screen-absolute-coordinates-via-skcanvas-ctm--done).

#### End-to-end verification

`uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz`
produced, in a single ~35-second run:

- 478 unique `text` lines (hb_shape_full path, unchanged from Phase 5).
- 856 `draw_text DrawTextBlob` records with x ∈ [16, 950], y ∈ [17, 244+].
  The y-stride 28 px on the sidebar and 36 px in the body paragraphs
  matches Wikipedia's typography; x clustering at 28, 264, 318, 769, 859
  matches the expected nav / content / infobox columns.
- Zero `kDrawSlug` records in this build for this URL.

Hook fires only in the gpu-process; renderer logs `hb_shape_full`
hooks but skips the dispatcher (it's not on the hot path there).

### Phase 7 — Filled-rectangle capture (`draw_rect` events) — DONE

Adds geometric scaffolding the eventual ASCII renderer needs behind text:
box backgrounds, button surfaces, divider rules, focus rings. Output stream
now includes a third record kind alongside `text` and `draw_text`:

```
{type:"draw_rect", kind:"SkRect"|"DrawRect"|"DrawRRect"|"DrawIRect"|"DrawOval",
 pid, left, top, right, bottom, color, op}
```

#### Hook targets & rationale

Four cc::PaintOp types carry filled-rect geometry: `kDrawRect`(18),
`kDrawRRect`(19), `kDrawIRect`(12), `kDrawOval`(15). All inherit
`PaintOpWithFlagsBaseInternal`, putting their geometry field at op+0x50
(verified by disassembling each inlined / out-of-line case in the
dispatcher and matching `add $0x50,%r14` before the `SkCanvas::draw*`
call).

Three hook strategies in parallel — the first one that fires for any
given rect wins via the dedupe LRU. Real wall-clock data on Wikipedia:

1. **PaintOpWithFlags::RasterWithFlags dispatcher** (`0x3f59ad0`) —
   reused from Phase 6 with extended type filter. **Almost never sees
   rect ops in this build**: clang LTO inlines the simple-rect cases of
   `cc::PaintOpBuffer::Playback` so aggressively that the only
   reachable out-of-line call to the dispatcher (single `call`
   instruction in the whole binary, at `0x3f6b404`) dispatches just
   kDrawTextBlob and kSaveLayer in the steady state. Kept for parity
   with Phase 6 and in case future builds break the inlining.
2. **Per-op static `T::RasterWithFlags`** — `0x595a250` (DrawRect),
   `0x3deabc0` (DrawRRect), `0x3df0d20` (DrawIRect), `0x3de6020`
   (DrawOval). These are the `g_raster_with_flags_functions[k]`
   slots resolved through the jmp-stub table at `11a5edb0` / `b8` /
   `d80` / `d98`. Fire for the rare cases LTO didn't inline; produce
   ~7 records on a full Wikipedia load. They DO emit colour via the
   PaintFlags `color_` field (SkColor4f f32x4 RGBA at `flags+0`).
3. **SkCanvas::drawRect** (`0x3f71470`) — the catch-all Skia entry.
   Fires ~640 times on a full Wikipedia load, capturing rectangles
   from every code path the cc-layer hooks miss. Geometry only;
   colour decode of SkPaint is version-fragile and deferred — but
   geometry alone is enough for the ASCII-render scaffold this phase
   exists for. Records carry `op:"0x0"` since SkCanvas has no
   corresponding PaintOp pointer.

Records are deduped by `kind|⌊l⌋,⌊t⌋,⌊r⌋,⌊b⌋|color` in a 16 K LRU per
process (4× the text LRU) so wiggle from CTM rounding doesn't explode
the cache.

#### What's deferred

- **Colour for SkRect records.** SkPaint's layout (4-bit refcount,
  colour-space ptr, draw-looper, shaders, etc.) changes between Skia
  versions; reading colour from `args[2]` here would need its own
  little refresh workflow. The PaintFlags-bearing per-op hooks already
  emit colour for the small slice of records that flow through them.
- **CTM** resolved in Phase 8; absolute `(sleft, stop, sright, sbottom)`
  now ride alongside the layer-local `(l,t,r,b)` on every record.
- **Non-rectangular fills** (DrawPath, DrawArc, DrawDRRect): not in
  this phase. DrawTextBlob already captures text geometry; everything
  else falls in a future phase if needed.

#### End-to-end verification

`uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz`
produced, in a single ~30-second run on Brave 1.90.122-1:

- 7182 unique `text` lines (hb_shape_full path, unchanged).
- 5140 `draw_text DrawTextBlob` records (Phase 6 path).
- 640 `draw_rect` records: 633 `SkRect` (geometry-only) + 7
  PaintOp-typed (DrawIRect / etc., with colour). Left coordinates
  span 0.00 → 1186.00, right coordinates 2.00 → 1296.00 — matches the
  viewport width Brave painted into.

### Phase 8 — Screen-absolute coordinates via SkCanvas CTM — DONE

Adds the current-transform matrix to every draw record so the consumer can
map layer-local pre-CTM `(x, y)` to screen-absolute `(sx, sy)`. Output stream
records gain three optional fields:

- `sx`, `sy` on `draw_text DrawTextBlob` — the CTM-transformed origin.
- `sleft`, `stop`, `sright`, `sbottom` on `draw_rect` — the CTM-transformed
  bounds.
- `ctm` — 6-float 2D-affine row `[m00, m01, m03, m10, m11, m13]` extracted
  from the SkM44, so downstream tooling can transform any other point in
  the same record without re-deriving Skia's storage convention. `DrawSlug`
  records carry only `ctm` (slug data not yet decoded).

Layer-local `(x, y)` / `(left, top, right, bottom)` are retained verbatim;
nothing was replaced. The `draw_rect` dedupe key now uses
**absolute-quantised** bounds, so the same logical rect painted at two
different scroll offsets shows up as two records (previously collapsed).

#### Hook target & strategy

Strategy A from the design brief: read SkCanvas's CTM directly via fixed
field offsets. No new hook; piggybacks on the existing dispatcher /
per-op / SkCanvas::drawRect hooks. SkCanvas exposes its current matrix
through a `MCRec* fMCRec` member (top-of-stack of the matrix-clip
record). MCRec contains `SkM44 fMatrix` (16 column-major f32).

Offsets verified by disassembling two unrelated SkCanvas methods in
Brave 1.90.122-1 (`SkCanvas::drawRect` at `0x3f71470` and
`SkCanvas::drawTextBlob` at `0x3f61330`). Both emit the same matrix-load
pattern verbatim:

```
mov 0x640(this), %rNN     ; load fMCRec pointer
add $0x18, %rNN           ; point at MCRec::fMatrix
lea &rect, %rsi           ; second arg
call SkM44::mapRect       ; transforms the rect via the matrix
```

→ `fMCRec` at SkCanvas+0x640; `fMatrix` at MCRec+0x18; format is SkM44
column-major (`SkScalar fMat[16]`, `(r,c) = fMat[c*4 + r]`). For a 2D
affine, `sx = m[0]*x + m[4]*y + m[12]`, `sy = m[1]*x + m[5]*y + m[13]`.

Pinned in `signatures.json` as `sk_canvas_mcrec_offset` (`0x640`),
`mcrec_matrix_offset` (`0x18`), `ctm_matrix_kind` (`SkM44`).

Strategies B (call `getLocalToDevice()` via `NativeFunction`) and C
(track save/restore in JS) were not needed.

#### Why this is safe

The four hooks where we want the CTM each already see a `SkCanvas*` in
their argument frame:

| hook | canvas register |
| --- | --- |
| `PaintOpWithFlags::RasterWithFlags` (dispatcher) | rsi (args[1]) |
| `T::RasterWithFlags` (per-op) | rdx (args[2]) |
| `SkCanvas::drawRect` | rdi (args[0]) |

A null-safe `readCTM(canvas)` helper does `canvas+0x640 → MCRec → +0x18
→ 16 f32` and returns the 2D-affine row; null/read-error returns null
and the record is emitted without `sx/sy` fields (graceful degradation).

#### Tile-translate noise

The raster path processes one cc-tile at a time, so the CTM at hook
entry often includes a per-tile translation. The PoC accepts this — the
absolute values are still consistent because the per-tile translation
*is* the tile's position on the surface. The Wikipedia run showed sy
clusters at 17 (top chrome), 38 (title row), 119/155/191/231 (body
paragraphs, 36 px stride), with no tile-edge artefacts in the column
of x values.

#### End-to-end verification

`uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz`
on Brave 1.90.122-1 produced (~30 s, no manual scroll):

- 1035 `draw_text DrawTextBlob` records, every one carrying both
  `(x,y)` and `(sx,sy)`. sx ∈ [16, 1296], sy ∈ [16, 244+] — matches
  Wikipedia's viewport bounds.
- 125 `draw_rect` records with paired `(l,t,r,b)` / `(sleft,…,sbottom)`.
  CTM-translated rects are clearly visible — e.g. `sl=19 st=10 sr=267
  sb=51 (l=0 t=0 r=248 b=41)` is a layer-local origin-rooted rect being
  composited at viewport offset (19, 10) — i.e. through a translation
  layer Wikipedia uses for its header bar.
- Layer-local-only-rendered text (no transform layer) shows `sx == x`
  and `sy == y` — the identity matrix case, also confirmed.
- 1841 records total across both kinds; no `error:` lines in stderr,
  all eight `hooked:` lines present (hb_shape_full +
  PaintOpWithFlags::RasterWithFlags + four per-op + SkCanvas::drawRect).

Scroll-correlation note: the automated 30-s run doesn't scroll. In
interactive use (Ctrl-C late), repeated paints of the same op pointer
at different scroll offsets emit different `sy` values with identical
`y` — the diff in `sy` matches the scroll delta. The same op-pointer
appearing 16× with identical `(sx, sy)` for the sticky-header text
confirms the hook isn't accidentally accumulating noise; it's reading
the actual current matrix each time.

### Phase 9 — JSONL tee + ASCII renderer (consumer pipeline) — DONE

First consumer of the structured capture stream. Capture side now optionally
tees raw records to a JSONL file; a separate Python script consumes that
file and emits an ASCII reconstruction of the painted page.

#### `run.py --jsonl <path>`

Opt-in flag. When set, every `text` / `draw_text` / `draw_rect` payload
the Frida agent sends is also written verbatim (one JSON object per line)
to the given file, in addition to the existing humanised stdout stream.
Meta records (`hooked`, `ready`, `skip`, `warn`, `error`, `dump`) stay
on stderr — the JSONL file is a pure capture-event stream so the
renderer doesn't have to filter. Truncates on open; one run = one file.

A single `threading.Lock` guards writes since Frida invokes the message
callback on its own thread.

#### `render_ascii.py`

New file, stdlib only. Reads JSONL (or stdin), prints an ASCII grid.

Algorithm:

1. Walk the JSONL once. Keep one global FIFO of pending shaped strings;
   each `text` record enqueues, each `draw_text DrawTextBlob` record
   dequeues one and pairs it with `(sx, sy)`. Records without
   coordinates (`DrawSlug`, missing `sx`/`sy`) still dequeue to keep
   the FIFO from drifting away from the position stream.
2. Quantise to a configurable cell size (default 8×16 px). Grid size is
   `max_sx/cell_w` × `max_sy/cell_h`, capped at 400×200 to keep
   pathological captures from blowing memory.
3. Pass 1 (backgrounds): every `draw_rect` paints a shade char into its
   cell range based on the SkColor4f luminance ramp ` ░▒▓█`. Records
   without colour (the SkCanvas::drawRect catch-all) use `.` so they're
   visible but unobtrusive.
4. Pass 2 (text overlay): every correlated `draw_text` writes the
   placed string left-to-right starting at `(sx//cell_w, sy//cell_h)`.
   Non-ASCII codepoints render as `?`.

CLI:

```
uv run python render_ascii.py capture.jsonl
uv run python render_ascii.py --cell 8x16 --out frame.txt capture.jsonl
uv run python render_ascii.py --stats capture.jsonl       # diagnostics to stderr
```

#### Correlation: why a global FIFO

`text` records originate in the **renderer process** (hb_shape_full hook);
`draw_text` records originate in the **gpu-process** (PaintOpWithFlags
dispatcher hook). They cross process boundaries, ride two different
Frida sessions, and arrive at `run.py` on different threads. There is
no shared identifier: hb_shape_full sees a HarfBuzz buffer pointer; the
PaintOp dispatcher sees a `cc::DrawTextBlobOp*` (which holds a *post-
shaping* `SkTextBlob`, not the buffer).

A global FIFO is the cheapest correlator that gets *useful* output. It
drifts when one stream is faster than the other (e.g. the gpu-process
hook fires for chrome decorations that never went through hb_shape_full,
or hb_shape_full fires for offscreen text that never gets painted).
Drift manifests as text content shifted N positions in the grid —
visible in the Wikipedia test as adjacent words landing on the wrong
line, but the page is still recognisable.

A smarter correlator would need either a per-buffer identifier passed
through SkTextBlob's storage (Skia-version-sensitive, deferred) or
shape-time text-blob fingerprinting (run length + first-codepoint match,
worth trying in Phase 10 if drift becomes blocking).

#### End-to-end verification

`uv run python run.py --jsonl capture.jsonl -- --new-window
https://en.wikipedia.org/wiki/HarfBuzz` for ~25 s produced 942 `text`,
1051 `draw_text`, 128 `draw_rect` records. `render_ascii.py --stats`
reported `placed=942 no_text=109 no_xy=0 unmatched_text=0` — i.e. 109
draw_text events ran ahead of their text content (acceptable drift).
The resulting ASCII grid (200 rows × 400 cols default) shows
recognisable Wikipedia content: "Open Baskerville", "Donald Knuth",
"Universal Shaping Engine", "By Default", "Cairo or Skia", "Apple
Advanced Typography", "registered trademark of the Wikimedia
Foundation". Body text is cramped into the top ~25 rows because all
text events correlate to the relatively small set of `draw_text`
positions that fired in this short capture; lower rows are mostly
background-only.

#### Known limits

- **Smearing under scroll.** No frame boundaries in the stream — the
  rendered grid is the cumulative composite of every text run and rect
  that ever fired. Scrolled / re-painted regions overlap. A `--frame-by-time`
  partition would be the obvious Phase 10 step.
- **FIFO drift.** As above; ~10 % unmatched draw_text in a 25 s
  Wikipedia capture.
- **No font-size awareness.** All text is laid out at the same cell
  width regardless of the real rendered size. Headings and body text
  occupy the same row height in the grid.
- **Chrome decorations leak in.** SkCanvas::drawRect catches the
  browser chrome (sidebar dividers, tab outlines), not just page content.

## Backlog / known limits

- **Text fragmented at shape-run boundaries.** HarfBuzz shapes one
  script-run / font-fallback region at a time, so "Cwm fjordbank, vext
  quiz, 😃 glyphs" can land as separate captures for `Cwm`, `fjordbank`,
  `vext quiz`, `😃`, `glyphs`. Reconstruction would need correlating runs
  by buffer pointer and cluster index — out of PoC scope.
- **Glyph IDs vs Unicode.** We hook before shaping, so we always get
  readable codepoints. Post-shaping (what actually rasterized to pixels)
  would mean hooking `SkCanvas::onDrawTextBlob` — and losing readability.
- **No viewport awareness.** Off-screen and hidden DOM text still gets
  shaped, so will be captured. Adding a viewport filter would require
  also hooking compositor layer commits.
- **Cross-process dedupe.** Per-renderer LRU only. Two tabs rendering the
  same content yield duplicates on stdout.
- **No canvas / WebGL.** `<canvas>` `fillText` may bypass HarfBuzz
  entirely depending on the Skia path; WebGL text is invisible.
- **Single Brave build at a time.** Offsets pin to the build-id in
  `signatures.json`. Brave upgrade silently breaks the hook — agent
  attaches but at the wrong address. Refresh via
  [FINDING_OFFSETS.md](./FINDING_OFFSETS.md).
- **No chrome:// filter.** `chrome://settings`, `chrome://version`, etc.
  render in regular renderer processes; their text is captured too.
  Filter on the consumer side if you want web-only output.

## Portability sketch

Same technique should transfer to Chrome, Edge, Opera, and other
Chromium-based browsers with statically-linked HarfBuzz:

- Anchors are HarfBuzz's, not Brave's — `HB_SHAPER_LIST` works anywhere
  HarfBuzz is statically linked.
- Buffer offsets are HarfBuzz-version-tied (not browser-tied).
- `run.py` would need profile dir, ozone flag, and Brave-specific arg
  changes.
- `capture.js`'s `BRAVE_PATH_HINT` becomes browser-specific.

Untried but believed straightforward.
