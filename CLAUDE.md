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

## Repository layout (target)

```
brave-frida-capture/
  CLAUDE.md          — this file
  PLAN.md            — implementation plan, status, backlogs
  run.py             — launcher: profile dir + spawn brave + frida attach + print
  capture.js         — frida agent: hooks hb_buffer_add_utf16, sends text back
  signatures.json    — { "hb_buffer_add_utf16": <file_offset_hex>, ... }
  README.md          — user-facing run instructions (written last)
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
| frida-tools (CLI, what `uvx` runs) | https://github.com/frida/frida-tools |
| `frida-python` API | https://github.com/frida/frida-python |
| Gum JavaScript API docs | https://frida.re/docs/javascript-api/ |
| Module / Memory / Interceptor docs | https://frida.re/docs/javascript-api/#module , `#memory`, `#interceptor` |
| Child gating notes | https://frida.re/news/2018/03/27/frida-10-7-released/ |
| Invocation: `uvx --from frida-tools frida ...` (v17.9.10 confirmed) | local |

### Binary Ninja MCP (used to find offsets in the stripped binary)

| What | Where |
| --- | --- |
| MCP server in use | BinAssistMCP — `http://localhost:8000/mcp` (Streamable HTTP) |
| Registered in this Claude as | `binassist` (user scope, in `~/.claude.json`) |
| Binary Ninja product | https://binary.ninja/ |
| Tool prefix used here | `mcp__binassist__*` (e.g. `search_strings`, `xrefs`, `get_code`) |
| Currently loaded binary | `brave` → `/opt/brave-bin/brave` |
| **Binja → real VA offset** | **Binja reports addresses with a +0x400000 analysis base.** Subtract 0x400000 from every address Binja returns to get the actual virtual address (matches both file offset and runtime VA, since the binary maps with `p_offset == p_vaddr` for the first PT_LOAD). Confirmed empirically and by user. |

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

## Confirmed anchors (real VAs)

| Symbol | VA | Notes |
| --- | --- | --- |
| `HB_SHAPER_LIST` (string) | `0x1f22292` | length 14, in `.rodata` |
| `hb_options_init` | `0x69df290` | only xref to `HB_SHAPER_LIST`; verified by disassembly (calls `getenv("HB_SHAPER_LIST")`, parses comma-separated tokens with `strchr`/`strlen`) |
| `getenv@plt` | `0x10df8b30` | from PLT trampoline reachable from `hb_options_init+0x25` |

Helper scripts under `tools/`:

- `find_xref.py <hex_target_va>` — scans `.text` for all 7-byte RIP-relative `LEA` instructions whose disp resolves to the target VA. Finds string xrefs in PIE binaries even when Binja analysis is incomplete.
- `find_hb_buffer_add.py` — attempted wildcard prologue scan for `hb_buffer_add_utf16`/`utf8`. **Currently returns 0 hits.** Pattern needs revision (chromium 13.1.0's `hb_buffer_t` field layout differs from system 14.2.0; clang prologue choices differ from system gcc).

## Layout note for the `hb_buffer_t` chase

In chromium's vendored HarfBuzz 13.1.0:

```
offset  field
0x00    hb_object_header_t (16 B: ref_count + writable + user_data)
0x10    hb_unicode_funcs_t *unicode
0x18    hb_buffer_flags_t flags
0x1c    hb_buffer_cluster_level_t cluster_level
0x20    hb_codepoint_t replacement
0x24    hb_codepoint_t invisible
0x28    hb_codepoint_t not_found
0x2c    hb_codepoint_t not_found_variation_selector
0x30    hb_buffer_content_type_t content_type
0x34    hb_segment_properties_t props
...
+??     bool successful, bool have_output, bool have_positions
+??     unsigned idx, unsigned len, unsigned out_len, unsigned allocated
+??     hb_glyph_info_t *info, *out_info, hb_glyph_position_t *pos
```

The system-14.2.0 disassembly we used to derive the prologue scan read at offsets `0x4` and `0x20` — but in 13.1.0 those are `header.writable` (1 B) and `replacement` (4 B), not `successful` and `len`. So the scan was checking the wrong field accesses. Future attempts should:

1. Compile the chromium-vendored HarfBuzz standalone with the same chromium toolchain (clang from `chromium/src/third_party/llvm-build/`) to get a byte-accurate reference, OR
2. Read the C source for `hb_buffer_add_utf<utf16_t>` (in `hb-buffer.cc`) and derive a more robust semantic pattern (calls into `hb_buffer_pre_allocate` template — that has a distinctive `hb_realloc` call sequence), OR
3. Just wait for Binja's full analysis (`mcp__binassist__update_analysis_and_wait`), then use `mcp__binassist__xrefs` and `get_code` to find functions reliably.
