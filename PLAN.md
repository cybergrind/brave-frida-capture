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
