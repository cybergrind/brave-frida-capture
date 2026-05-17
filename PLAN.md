# Implementation Plan

Companion to [CLAUDE.md](./CLAUDE.md) — read that first for the goal,
constraints, and source-tree map. This file is the working plan: phases,
status, what to do when something breaks.

## Architecture, one diagram

```
   ┌──────────────────────────────────────────────────────────────┐
   │  run.py (host)                                               │
   │                                                              │
   │   1. ensure ~/.config/BraveSoftware/brave-frida/             │
   │   2. frida.spawn("/opt/brave-bin/brave",                     │
   │        argv=[--no-sandbox, --user-data-dir=..., ...])        │
   │   3. session.enable_child_gating()                           │
   │   4. on every child: inject capture.js, set offsets          │
   │   5. on message: print captured text                         │
   └──────────────────────────────────────────────────────────────┘
                                │  spawn + frida-server-less inject
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  brave (browser process)  ─── child gating ───►  renderer #N │
   │                                                              │
   │   capture.js loaded into each process. Early-exit if         │
   │   /proc/self/cmdline does NOT contain "--type=renderer".     │
   │                                                              │
   │   In renderers:                                              │
   │     base = Module.findBaseAddress("brave")                   │
   │     Interceptor.attach(base + sig.hb_buffer_add_utf16, {     │
   │       onEnter(args) {                                        │
   │         const text  = args[1];   // uint16_t*                │
   │         const len16 = args[2].toInt32();                     │
   │         const s     = text.readUtf16String(len16);           │
   │         dedupe.add(s) && send({type:"text", pid, text:s});   │
   │       }                                                      │
   │     });                                                      │
   └──────────────────────────────────────────────────────────────┘
```

## Phases

### Phase 1 — Find offsets in `/opt/brave-bin/brave` (Binja MCP)

Status: **partially blocked.** Got one HarfBuzz anchor confirmed; pattern-based hunt for the actual hook targets failed and needs a different approach. See "Confirmed anchors" in [CLAUDE.md](./CLAUDE.md) for what's solid.

Findings to date:

- `HB_SHAPER_LIST` string at VA `0x1f22292`, exactly one xref from VA `0x69df2ae`.
- That xref is inside the function at VA `0x69df290` — **confirmed to be `hb_options_init`** by reading the disassembly (`getenv("HB_SHAPER_LIST")` followed by a `strchr(',')` / `strlen` token-parsing loop).
- **Binja MCP address skew:** Binja reports addresses with a +0x400000 analysis base. Subtract 0x400000 from anything `mcp__binassist__*` returns. (Recorded permanently in CLAUDE.md.)
- **Chromium uses `-fcf-protection=none`** — no `endbr64` bytes in `.text`. Don't use endbr as an anchor.
- **Byte-pattern scan failed.** A wildcard prologue scan against system `libharfbuzz.so` (14.2.0) returned 0 hits in brave's HarfBuzz (13.1.0). Root cause: `hb_buffer_t` field layout differs between versions, so the "read +0x20 / read +0x4" pattern from 14.2.0 doesn't apply to 13.1.0. Tooling lives under `tools/`.

Open paths to find `hb_buffer_add_utf16` / `hb_shape_full`:

- **A. Wait for Binja's full analysis**, then call `mcp__binassist__update_analysis_and_wait` to confirm, and use `xrefs` from `hb_options_init` and nearby HarfBuzz functions to walk the static-link cluster. Once any other named-by-source HB function (e.g. `hb_blob_create`) is identified, its neighbors are findable. Slow but reliable.
- **B. Source-build the chromium-vendored HarfBuzz with chromium's clang.** Use `chromium/src/third_party/llvm-build/Release+Asserts/bin/clang++` against `chromium/src/third_party/harfbuzz-ng/src/src/`. Get a byte-accurate reference for `hb_buffer_add_utf16` and `hb_shape_full`, then run the wildcard scan with versions that actually match.
- **C. Dynamic discovery via Frida.** Hook `getenv` in `libc.so.6` (dynamically linked, easy). When called with arg `"HB_SHAPER_LIST"`, capture `this.returnAddress` — that's an address inside `hb_options_init`. From that runtime anchor, walk to nearby module memory and look for hb_buffer_add_utf16 candidates by structural disassembly via Frida's Capstone wrapper. This doesn't directly identify the function but provides a runtime sanity check on offsets from path A/B.
- **D. Use Binja interactively in the UI** (no MCP) to navigate from `0x69df290` (real VA) → adjacent functions in the HarfBuzz cluster. The user can rename functions in the UI and the renames become visible to MCP. This is the fastest path if the user is willing to drive Binja manually for a few minutes.

Recommended next step: **try (A) — let Binja finish analysis, then re-query MCP.** Falls back to (B) if Binja can't resolve functions cleanly.

Anchor-driven walk:

1. Search `.rodata` for HarfBuzz-distinctive strings:
   - `HB_SHAPER_LIST` (env var read by `hb_shape_list_shapers`) — **found at
     `0x2322292`**.
   - `RenderTextHarfBuzz::*` trace event names — abundant; these are Chromium's
     `ui/gfx/render_text_harfbuzz.cc`, not HarfBuzz itself. Useful for finding
     Chromium-side text shaping callers but not the HB API targets.
   - Backup anchors if needed: `"%c%c%c%c"`, `"ot"`/`"fallback"` shaper names
     in the shapers table, the version string `"13.1.0"`.
2. `xrefs` on each anchor to find the function reading the string.
3. `get_code` (pseudo_c) on candidates to verify against the upstream C source
   from `chromium/src/third_party/harfbuzz-ng/src/src/hb-buffer.cc` and
   `hb-shape.cc`.
4. For each confirmed function, record the virtual address. Convert to file
   offset by subtracting the load base of the segment it lives in. (Brave is
   PIE — Frida loads it at a random base; we only need the offset relative to
   `Module.findBaseAddress("brave")`, which is the same as the file offset for
   the `.text` mapping.)
5. Save to `signatures.json`:
   ```json
   {
     "brave_build_id": "d6091daa9f05eabe47eb1dcbe13ba40babb32521",
     "offsets": {
       "hb_buffer_add_utf16": "0x...",
       "hb_shape": "0x..."
     }
   }
   ```

**Caveat from analysis state.** Binja reported `analysis_complete: false` for a
283 MB binary. `update_analysis_and_wait` could take hours. Strategy: skip the
wait — `search_strings` and `xrefs` work on partial analysis; if `get_code`
returns a stub, force-analyze only the candidate functions individually.

**Why two targets, not just `hb_buffer_add_utf16`.**
- `hb_buffer_add_utf16` gives us the raw input text — primary signal.
- `hb_shape` is the actual shaping call; useful as a secondary trigger and for
  filtering (if `hb_shape` was never called, the text wasn't actually rendered).
  Hooking both also lets us correlate by buffer pointer.

### Phase 2 — Scaffold `run.py` + `signatures.json`

Status: pending.

Responsibilities of `run.py`:

- Resolve Brave binary path (default `/opt/brave-bin/brave`, overridable via
  `--brave`).
- Ensure `~/.config/BraveSoftware/brave-frida/` exists; pass as
  `--user-data-dir`. **Do not delete it between runs** — persistence is a
  user requirement.
- Build the spawn argv:
  ```
  --no-sandbox
  --user-data-dir=<profile>
  --no-first-run
  --disable-features=RendererCodeIntegrity
  ```
- Use `frida.get_local_device().spawn(...)` then `attach()`, then
  `session.enable_child_gating()` so renderer children get the agent injected
  too.
- Load `capture.js`, send `{type:"signatures", offsets:{...}}` via
  `script.post(...)`, then `resume()` the spawned process.
- Pump messages: print `{type:"text"}` payloads as `[pid N] <text>`.
- Use `uvx --from frida-tools` — but actually `frida-tools` ships
  `frida-python` too, so the cleanest approach is for `run.py` to be invoked
  via `uvx --from frida-tools --with frida python run.py`. Test what the host
  actually has first; document in README.

### Phase 3 — `capture.js` Frida agent

Status: pending.

Skeleton (this is design, not final code):

```js
let OFFSETS = null;

recv("signatures", msg => {
  OFFSETS = msg.payload.offsets;
  install();
});

function install() {
  const argv0 = readCmdline();
  if (!argv0.includes("--type=renderer")) return;

  const base = Module.findBaseAddress("brave");
  if (!base) { send({type:"error", msg:"no brave module"}); return; }

  const addr = base.add(parseInt(OFFSETS.hb_buffer_add_utf16, 16));
  const seen = new Map();   // small LRU keyed by string

  Interceptor.attach(addr, {
    onEnter(args) {
      const textPtr = args[1];
      const len16   = args[2].toInt32();
      if (len16 <= 0 || len16 > 1 << 20) return;
      const s = textPtr.readUtf16String(len16);
      if (!s || seen.has(s)) return;
      if (seen.size > 4096) seen.delete(seen.keys().next().value);
      seen.set(s, 1);
      send({type:"text", text: s});
    }
  });
}
```

Edge cases:

- `Module.findBaseAddress("brave")` may need the basename actually used by the
  loader — could be `"brave"` or full path. Try both.
- Some renderer processes are utility processes that also have `--type=...`;
  filter for `--type=renderer` specifically.
- High-volume dedupe: per-process LRU is fine; cross-process dedupe is the
  Python side's job if we want it.

### Phase 4 — README and refresh workflow

Status: pending.

Must document:

- Install prereqs (`uv`, Brave, Binja with BinAssist MCP plugin if regenerating
  offsets).
- How to run: `./run.py` and what to expect on stdout.
- **Signature refresh procedure** for when Brave updates: open new Brave in
  Binja → connect MCP → re-run anchor search → update `signatures.json` +
  `brave_build_id`. Future Claude sessions can do this end-to-end.
- Known limits:
  - No canvas/WebGL rendered text (no shaping path).
  - Text in hidden/off-screen DOM still gets shaped → captured.
  - `--no-sandbox` is required; treat the PoC profile as untrusted.
  - One Brave version at a time; signatures don't carry across builds.

### Phase 5 — Test

Status: **done.** PoC captures real page text end-to-end.

Two adjustments forced by reality:

1. **Don't `frida.spawn()` Brave.** Holding Brave under Frida child-gating
   stalled Brave's startup — gpu / utility / broker / renderer processes
   never came up, only zygote + crashpad-handler. Switched to launching
   Brave with `subprocess.Popen` and using Frida solely to *attach* to
   renderers as they appear in `/proc` (matched by `--user-data-dir=` to
   our profile so we don't attach to the user's other Brave instance).
2. **Read `~/.config/brave-flags.conf`.** The user's Wayland desktop needs
   `--ozone-platform=wayland` for Brave to create a window at all. The
   system `/usr/bin/brave` wrapper applies that conf; our launcher
   bypasses the wrapper, so it now reads the same conf inline.

Sample observed output for `--new-window https://en.wikipedia.org/wiki/HarfBuzz`:

```
[pid N] About Wikipedia
[pid N] From Wikipedia, the free encyclopedia
[pid N] Apple Advanced Typography shaping,
[pid N] Core Text, the macOS equivalent (HarfBuzz can be used as an alternative on macOS)
[pid N] 14.2.0
[pid N] (20 April 2026; 23 days ago) [±]
... 482 total
```

All match visible page content (body text, sidebar, infobox, references).

### Important architecture change discovered during verification

The first hook target (`hb_buffer_add_utf16`) was **insufficient.** Blink's
`harfbuzz_shaper.cc` and `case_mapping_harfbuzz_buffer_filler.cc` both have:

```cpp
if (text.Is8Bit()) {
  hb_buffer_add_latin1(buffer, span.data(), span.size(), ...);
} else {
  hb_buffer_add_utf16(buffer, span.data(), span.size(), ...);
}
```

So ASCII text (the majority of web content) goes through `hb_buffer_add_latin1`,
which we weren't hooking. The first test run only captured `Cwm fjordbank gly[phs] 😃`
because that's Chromium's font-coverage probe text — full of non-Latin-1
codepoints that hit `hb_buffer_add_utf16`. Real page ASCII text went uncaught.

**Fix:** hook `hb_shape_full` instead. It runs after the buffer is fully
populated regardless of which `hb_buffer_add_*` filled it. Read the buffer's
`info[]` array; each 20-byte slot starts with the input codepoint (uint32).

Verified `hb_buffer_t` field offsets in chromium-vendored HarfBuzz 13.1.0:
- `+0x60`: `unsigned int len` (confirmed by hb_shape_full's `mov 0x60(%rsi),%eax; test %eax,%eax; je <bail>`)
- `+0x70`: `hb_glyph_info_t *info` (confirmed by diagnostic dump)
- `hb_glyph_info_t` stride: 20 bytes; `.codepoint` (uint32) at offset 0

Diagnostic dump from a captured buffer:
```
+0x60: 3c 00 00 00 ...   ; len = 60
+0x70: 00 95 0e 00 54 26 00 00   ; info = 0x2654000e9500
info[0]: 50 00 00 00 ...   ; codepoint = 0x50 = 'P'
```
…which matches the first char of "Please confirm that you and not a robot…".

- Launch via `run.py`.
- Navigate to: a static text-heavy article (e.g. a Wikipedia page),
  `about:blank` (sanity, should be silent), `chrome://version` (catches us
  capturing chrome UI text — should NOT, because chrome:// pages render in a
  renderer, so we WILL capture them; document this clearly).
- Spot-check: visible page text appears in output; clear browser UI strings
  (window title bar, menus) do not appear.

## Backlog / known limits / future work

- **Glyph IDs vs strings:** we hook before shaping, so we always get readable
  text. If we wanted post-shaping (i.e. what actually rasterized), we'd hook
  `SkCanvas::onDrawTextBlob` — and lose readability. Not worth it for this
  PoC.
- **Cross-process correlation:** currently each renderer dedupes
  independently. If two tabs render the same page we'll see strings twice.
  Fine for PoC.
- **Output formats:** currently stdout. Trivial follow-on to JSONL/SQLite.
- **Viewport awareness:** no signal here on whether shaped text is actually
  in the visible viewport. Would need to also hook compositor layer commits —
  much harder.
- **Other browsers:** the technique transfers to Chrome, Edge, Opera —
  same HarfBuzz, just different offsets.
