# brave-frida-capture

PoC for capturing every Unicode string Brave renders to a web page, by hooking
HarfBuzz with Frida inside renderer processes.

**Goal.** Print page text as it is being shaped for the screen — not browser
chrome, not DOM-only text, but exactly what passes through font shaping on its
way to the GPU.

**Approach in one sentence.** Hook `hb_shape_full` in each renderer; at entry
the input text sits in `buffer->info[i].codepoint` (uint32 per 20-byte slot)
regardless of whether Blink populated the buffer via `hb_buffer_add_latin1`
(ASCII path), `hb_buffer_add_utf16` (non-Latin-1 path), or any other route —
this is the single chokepoint that catches all page text.

See [PLAN.md](./PLAN.md) for the full implementation plan, current status, and
the workflow for refreshing function offsets when Brave updates.

---

## Why this is awkward

The user's installed Brave (`/opt/brave-bin/brave`, Arch `brave-bin` package)
is fully stripped. Only `ChromeMain` plus libc-overlap symbols are exported via
`.dynsym`. HarfBuzz, Skia, Blink, V8 — all statically linked, no symbols.
`Module.findExportByName(null, "hb_shape")` returns null. We work around this
by finding the function offsets once via Binary Ninja (over MCP), pinning them
in `signatures.json`, and using `Module.findBaseAddress("brave") + offset` at
runtime.

Renderer processes are sandboxed; Frida can't attach. PoC launches Brave with
`--no-sandbox`. Acceptable for a research tool, never for normal browsing.

## Repository layout

```
brave-frida-capture/
  CLAUDE.md             — this file
  PLAN.md               — design + as-built record
  README.md             — user-facing run instructions
  FINDING_OFFSETS.md    — refresh workflow when Brave updates (authoritative for that)
  run.py                — launcher: subprocess Brave, poll /proc for renderers, Frida-attach each
  capture.js            — Frida agent: hooks hb_shape_full, reads codepoints from buffer->info[]
  signatures.json       — per-build offsets + build-id + known anchors
  pyproject.toml        — `uv sync` then `uv run python run.py`
  tools/find_xref.py    — self-configuring `.text` LEA-xref scanner
  tools/find_hb_buffer_add.py — abandoned wildcard scan (kept for reference)
```

## Source repositories and key paths

### Brave

| What | Where |
| --- | --- |
| Brave Core (this user's checkout) | `/home/kpi/devel/opensource/brave-core` |
| Brave Core upstream | https://github.com/brave/brave-core |
| Brave Browser (umbrella, build scripts) | https://github.com/brave/brave-browser |
| Installed binary under test | `/opt/brave-bin/brave` (Arch `brave-bin` 1:1.89.145-1) |
| Launcher script (passes `brave-flags.conf`) | `/usr/bin/brave` |
| User profile we use | `~/.config/BraveSoftware/brave-frida/` |

### Chromium

| What | Where |
| --- | --- |
| Chromium src (this user's checkout) | `/home/kpi/devel/opensource/chromium/src` |
| Chromium code search | https://source.chromium.org/chromium/chromium/src |
| Blink text shaping | `third_party/blink/renderer/platform/fonts/shaping/` |
| HarfBuzz call site (entry into shaping) | `third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc` |
| Buffer-fill call site | `third_party/blink/renderer/platform/fonts/shaping/case_mapping_harfbuzz_buffer_filler.cc` |

The two call patterns to remember (both in renderer):
```cpp
// Populates the HarfBuzz buffer with UTF-16 source text — our hook target.
hb_buffer_add_utf16(hb_buffer, span.data(), span.size(), 0, text_.length());

// Triggers shaping; arg 2 is the same buffer.
hb_shape(hb_font, hb_buffer, nullptr, 0);
```

### HarfBuzz

| What | Where |
| --- | --- |
| Upstream | https://github.com/harfbuzz/harfbuzz |
| Version vendored in Chromium | 13.1.0 (commit `5d4e96ad8d00fc871ffa17707b2ca08fa850e7d6`) |
| Vendored source in user's tree | `/home/kpi/devel/opensource/chromium/src/third_party/harfbuzz-ng/src/` |
| System copy (reference for prototypes) | `/usr/lib/libharfbuzz.so.0.61420.0` (v14.2.0) |
| Public API headers | `third_party/harfbuzz-ng/src/src/hb-buffer.h`, `hb-shape.h` |
| `hb_buffer_add_utf16` definition | `third_party/harfbuzz-ng/src/src/hb-buffer.cc` |
| `hb_shape` definition | `third_party/harfbuzz-ng/src/src/hb-shape.cc` |
| README in chromium tree | `third_party/harfbuzz-ng/README.chromium` |

Function prototype we care about (from `hb-buffer.h`):
```c
void hb_buffer_add_utf16(hb_buffer_t  *buffer,
                         const uint16_t *text,
                         int           text_length,
                         unsigned int  item_offset,
                         int           item_length);
```
SystemV AMD64 calling convention puts `buffer` in `rdi`, `text` in `rsi`,
`text_length` in `edx`, `item_offset` in `ecx`, `item_length` in `r8d`.

### Frida

| What | Where |
| --- | --- |
| Frida core | https://github.com/frida/frida |
| frida-tools (CLI, installed via `uv sync`) | https://github.com/frida/frida-tools |
| `frida-python` API | https://github.com/frida/frida-python |
| Gum JavaScript API docs | https://frida.re/docs/javascript-api/ |
| Module / Memory / Interceptor docs | https://frida.re/docs/javascript-api/#module , `#memory`, `#interceptor` |
| Child gating notes | https://frida.re/news/2018/03/27/frida-10-7-released/ |
| Invocation: `uv run frida ...` (v17.9.10 confirmed) | local |

### Binary Ninja MCP (used to find offsets in the stripped binary)

| What | Where |
| --- | --- |
| MCP server in use | BinAssistMCP — `http://localhost:8000/mcp` (Streamable HTTP) |
| Registered in this Claude as | `binassist` (user scope, in `~/.claude.json`) |
| Binary Ninja product | https://binary.ninja/ |
| Tool prefix used here | `mcp__binassist__*` (e.g. `search_strings`, `xrefs`, `get_code`) |
| Currently loaded binary | `brave.bndb` → `/opt/brave-bin/brave` |
| **Binja → real VA offset** | Binja reports addresses in its own analysis-database space; for the current build, that's **`+0x400000`** above the real VA. This is **not universal** — measure first per [FINDING_OFFSETS.md § Critical concept](./FINDING_OFFSETS.md#critical-concept-binja-mcp-address-skew-measure-dont-assume) (compare `search_strings` for `HB_SHAPER_LIST` to `strings -t x`). Every Binja MCP return → subtract skew; every input → add skew. |

## Working agreements for future Claude sessions

- **Don't propose CDP / DevTools Protocol** as a substitute. The user explicitly
  chose Frida-based hooking; that constraint is load-bearing for the research
  goal ("what is actually being painted", not "what the DOM says").
- **Don't propose rebuilding Brave** unless the user asks. We committed to the
  pattern-scan / Binja-MCP path; rebuilding takes hours and ~50 GB.
- **Profile path is fixed.** Use `~/.config/BraveSoftware/brave-frida/` and
  re-use it across runs (the user wants persistence — cookies, logins, history
  across PoC sessions).
- **Don't pollute `brave-core`.** This PoC lives in its own directory
  intentionally; it is not Brave code and should not be PR'd upstream.
- **Sandbox flag is non-negotiable** for the PoC: Frida cannot attach to a
  sandboxed renderer. Document this loudly, never silently drop it.
- **Stripped binary realities:** every `hb_*` symbol we hook must be found by
  offset, not name. When Brave updates, signatures break — see PLAN.md for the
  refresh workflow.

## Quick references

- Brave version test was developed against: `1.89.145-1` (brave-bin Arch package)
- Chromium HarfBuzz revision: `5d4e96ad` / v13.1.0-26
- BuildID of `/opt/brave-bin/brave`: `d6091daa9f05eabe47eb1dcbe13ba40babb32521`
  — use to confirm signatures still apply after upgrades.

## Confirmed anchors (real VAs, for Brave 1.89.145-1)

| Symbol | VA | Notes |
| --- | --- | --- |
| `HB_SHAPER_LIST` (string) | `0x1f22292` | length 14, in `.rodata` |
| `hb_shapers_lazy_loader_create` | `0x69df290` | the lazy-init `create()` method of HarfBuzz's shapers loader (`third_party/harfbuzz-ng/src/src/hb-shaper.cc` around line 48). Only xref to `HB_SHAPER_LIST`. Verified by disassembly: calls `getenv("HB_SHAPER_LIST")`, allocates via `hb_calloc`, parses comma-separated tokens with `strchr`/`strlen`/`strncmp`. **Note:** this is NOT `hb_options_init` (a function name from older HarfBuzz that no longer exists in vendored 13.x). |
| `hb_shape_full` | `0x44c9070` | reached via xref-walk from `hb_shapers_lazy_loader_create` (one of two callers). The function `capture.js` actually hooks. |
| `hb_buffer_add_utf16` | `0x44bec70` | secondary anchor / sanity check. Found by walking from a Blink caller of `hb_shape_full`. |
| `getenv@plt` | `0x10df8b30` | PLT trampoline reachable from `hb_shapers_lazy_loader_create + 0x25`. |

The full step-by-step methodology — including how to identify these
functions in a fresh Brave build — lives in
[FINDING_OFFSETS.md](./FINDING_OFFSETS.md). Read that whenever Brave
upgrades and the build-id in `signatures.json` no longer matches.

Helper scripts under `tools/`:

- `find_xref.py <hex_target_va> [path/to/binary]` — scans the binary's first executable PT_LOAD segment for 7-byte RIP-relative `LEA` instructions whose disp resolves to the target VA. Reads PT_LOAD bounds dynamically (no per-build constants), so it works across Brave updates without changes.
- `find_hb_buffer_add.py` — abandoned wildcard-prologue scan. Kept for reference; not on the refresh path (it relied on system libharfbuzz 14.2.0 as a byte-template, which doesn't match chromium-vendored 13.1.0). The MCP-driven xref-chain in FINDING_OFFSETS.md replaced it.

## Buffer layout `capture.js` depends on (HarfBuzz 13.1.0, x86-64)

These are the only `hb_buffer_t` field offsets the agent reads at runtime:

| field | offset | size | used for |
| --- | --- | --- | --- |
| `header.writable` | `0x04` | 1 B | what `hb_buffer_add_utf16`'s prologue tests (`hb_object_is_immutable` check), used as a recognition heuristic in FINDING_OFFSETS.md |
| `len` (unsigned int) | `0x60` | 4 B | `BUF_LEN_OFF` in `capture.js`; iteration count for codepoint extraction |
| `info` (`hb_glyph_info_t *`) | `0x70` | 8 B | `BUF_INFO_OFF` in `capture.js`; base pointer to codepoint array |

`hb_glyph_info_t` is **20 bytes** (compile-time-guaranteed by
`static_assert (sizeof (hb_glyph_info_t) == 20)` in `hb-buffer.h`), with
`.codepoint` (uint32) at offset 0 — the input Unicode codepoint until
shaping replaces it with a glyph ID.

Full struct layout, alignment derivation, and the procedure for
re-deriving these offsets if HarfBuzz's major version changes are in
[FINDING_OFFSETS.md § Reference layout](./FINDING_OFFSETS.md#reference-layout-harfbuzz-1310-x86-64--only-fields-capturejs-touches).
