# FINDING_OFFSETS: how to refresh signatures.json for a new Brave build

This is the operating manual for re-locating the HarfBuzz functions we hook
inside a stripped Brave binary. Use it when:

- `signatures.json:brave_build_id` no longer matches
  `readelf -n /opt/brave-bin/brave | awk '/Build ID/ {print $NF}'` — Brave
  was upgraded.
- The capture script attaches and prints `hooked` lines but emits no `text`
  — offsets point at the wrong code.
- You want to verify a fresh checkout works end-to-end.

Read [CLAUDE.md](./CLAUDE.md) first for the project's goal and constraints.
Read [PLAN.md](./PLAN.md) for the design. This doc covers **only the
offset-refresh workflow**.

## TL;DR — what you're hunting

Two virtual addresses in `/opt/brave-bin/brave`, to drop into
`signatures.json`:

| key | what it is | size | how it's recognised |
| --- | --- | --- | --- |
| `hb_shape_full` | HarfBuzz's main shape entry; the function `capture.js` actually hooks | typically 1500–3000 B | 5 args; `mov 0x60(%rsi),%eax; test %eax,%eax; je <bail>` near the prologue (reads `buffer->len`, bails if zero); then `movw $0x0, 0xd0(%rsi)` AND `movl $0x0, 0xd8(%rsi)` (the `enter()` prelude: zeroes `allocated_var_bits`+`serial` and `scratch_flags`) |
| `hb_buffer_add_utf16` | retained as secondary anchor / sanity check; not on the hot path | ~400–800 B | 5 args; reads `header.writable` byte at `+0x4` and bails if `!= 1` (the `hb_object_is_immutable` check); then `cmp $0xffffffff` on both `%edx` (`text_length`) and `%r8d` (`item_length`) for the API sentinels; uses 2-byte-stride pointer arithmetic on `%rsi` (e.g. `lea (%rsi,%rax,2),...`) |

The hook code in `capture.js` doesn't need touching unless the *vendored
HarfBuzz version* itself changed — see "When HarfBuzz's struct layout
changes" below.

## Prerequisites

| Tool | Notes |
| --- | --- |
| **Binary Ninja** | Commercial edition (Personal forbids the plugin model BinAssist uses). Open `/opt/brave-bin/brave` and let analysis start — it doesn't have to be complete; we force it on demand below. The analysis DB in MCP is typically named `brave.bndb`; confirm with `mcp__binassist__list_binaries`. |
| **BinAssist MCP plugin** | Reachable at `http://localhost:8000/mcp`. `curl -X POST -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' http://localhost:8000/mcp` should return 200 in under 1s. Registered in `~/.claude.json` as `binassist`. **If you restart the MCP server, run `/mcp` in Claude Code to reconnect** — the old session ID is otherwise invalid and calls return `Bad Request: No valid session ID provided`. |
| **objdump, readelf** | binutils. Used for everything outside Binja so we don't depend on it being responsive. |
| **python3** | stdlib only — `tools/find_xref.py` uses no third-party libs. |
| **Chromium source checkout** | Anywhere on disk — we cite paths under `third_party/harfbuzz-ng/src/src/` to interpret disassembly. If you don't have one, [browse vendored HarfBuzz on GitHub](https://github.com/harfbuzz/harfbuzz/tree/main/src) at the matching version. |
| **uv** | Only needed for the final end-to-end verification (`uvx --from frida-tools python run.py`). |

The workflow assumes Brave is the Linux x86-64 Arch `brave-bin` package at
`/opt/brave-bin/brave`. For other distros / install methods (Flatpak, Snap,
.deb), replace the path everywhere; the techniques are unchanged.

## Critical concept: Binja MCP address skew (measure, don't assume)

Binja MCP returns addresses in *its own analysis-database address space*,
which can differ from the on-disk / runtime virtual addresses by a constant
offset. For the current brave build the offset is **`+0x400000`**, but
**do not assume this** — it depends on how Binja chose to rebase the
image, your Binja version, and the binary's own preferred load base.
Always measure first.

```bash
# Real VA in the file: equals file offset for anything in the first PT_LOAD
# (which covers .rodata). Confirm with:
readelf -lW /opt/brave-bin/brave | awk '/LOAD/'
#  — the first LOAD line should have Offset == VirtAddr (typically both 0).

strings -t x /opt/brave-bin/brave | grep -F 'HB_SHAPER_LIST'
#  → e.g. "1f22292 HB_SHAPER_LIST" — that hex is the real VA.
```

```text
# In Binja MCP:
mcp__binassist__search_strings(filename="brave.bndb", pattern="HB_SHAPER_LIST")
# → e.g. address "0x2322292"
```

`skew = binja_address - real_va` → `0x2322292 - 0x1f22292 = 0x400000`. From
now on:

- Every Binja MCP **return** address → subtract `skew` for objdump / Frida / signatures.json.
- Every address you **pass** to Binja MCP → add `skew`.

In example output below `skew = 0x400000` is shown but substitute yours.

(Subordinate: `.text` has an additional 0x1000 page-alignment skew between
file offset and VA, e.g. `Off 0x322a000` vs `VirtAddr 0x322b000`. You
almost never deal with this because `objdump -d` and `tools/find_xref.py`
operate on VAs; the tool reads PT_LOAD headers dynamically.)

## Step-by-step: refresh the offsets

All addresses below are **real VAs** unless explicitly marked `<binja>`
(= real + skew). The repo root is the cwd for every shell command.

### Step 1 — confirm the build actually changed

```bash
readelf -n /opt/brave-bin/brave | awk '/Build ID/ {print $NF}'
# compare against signatures.json:brave_build_id
```

Match → nothing to do. Mismatch → continue.

### Step 2 — locate `HB_SHAPER_LIST`, the seed anchor

The literal string `HB_SHAPER_LIST` is the name of an env var read by
exactly one place in HarfBuzz: the lazy initializer
`hb_shapers_lazy_loader_t::create()` in
`third_party/harfbuzz-ng/src/src/hb-shaper.cc` (around line 48). It's a
stable, well-known anchor that has survived every HarfBuzz refactor.

```text
mcp__binassist__search_strings(filename="brave.bndb", pattern="HB_SHAPER_LIST")
```

Note Binja's reported address; the real VA is that minus your skew. Cross-check:

```bash
strings -t x /opt/brave-bin/brave | grep -F 'HB_SHAPER_LIST'
```

(`HB_SHAPER_LIST` lives in `.rodata`, which is in the *first* PT_LOAD where
`p_offset == p_vaddr`, so strings(1)'s file offset equals the real VA.)

If `search_strings` returns nothing, see "Fallback anchors" below.

### Step 3 — find the lazy-loader function (the seed function)

The only xref to `HB_SHAPER_LIST` is a `lea ..., [rip+disp]` loading its
address into `%rdi` before `call getenv@plt`. The enclosing function is
`hb_shapers_lazy_loader_t::create` — the lazy `create()` method of the
shapers loader. (Older HarfBuzz had a separate `hb_options_init` function;
that's gone. Don't expect to find a symbol by that name.)

Via MCP, using Binja-space addresses:

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="<HB_SHAPER_LIST_binja_addr>",
                       direction="to")
# Expect 1 hit. Take its `address`, pass to:
mcp__binassist__get_parent_function(filename="brave.bndb",
                                     address="<the xref address>")
# → records the function start in Binja-space
```

**If Binja's analysis hasn't reached that region yet**, the xref may
report `function: null` and `get_parent_function` may time out. Sidestep
with our scanner (it reads `.text` bounds from the ELF, so no
per-build constants):

```bash
python3 tools/find_xref.py 0x<real_VA_of_HB_SHAPER_LIST>
# → prints each matching LEA's real VA; expect exactly 1 hit
```

If you get **2+ hits**: re-check you used the real VA (not Binja-space);
disassemble each hit and pick the one whose enclosing function calls
`getenv@plt` immediately after the LEA. If multiple sites all do that,
HarfBuzz changed — fall back to alternate anchors below.

If you get **0 hits**: you typed the wrong VA, or the string isn't where
you think it is. Go back to Step 2.

Find the function start by scanning backward from the hit for the prologue
(it sits right after the last run of `int3` (`cc`) padding):

```bash
HIT=0x<hit_va>
objdump -d --start-address=$((HIT - 0x300)) --stop-address=$((HIT + 0x40)) /opt/brave-bin/brave
```

Look for the most recent `push %rbp` / `mov %rsp,%rbp` after a run of `cc`
bytes. **Verify** by reading the function body — the rest of the
disassembly should call, in roughly this order:

```
call getenv@plt           ; reads the env var
... if env is non-null ...
call <hb_calloc>          ; allocates the shapers table (often resolves
                          ; to a libc alignment helper like __libc_memalign+0x10)
... token-parsing loop ...
call strchr@plt           ; (with $0x2c = ',' as second arg)
call strlen@plt
call strncmp@plt
```

If those calls aren't there in roughly that order, you didn't find the
right function.

Rename it in Binja:

```text
mcp__binassist__rename_symbol(filename="brave.bndb",
                               address_or_name="<func_start_binja_addr>",
                               new_name="hb_shapers_lazy_loader_create")
```

(Renaming is **required** because Step 4 uses `address_or_name="hb_shapers_lazy_loader_create"`
for the xref query. If you skip the rename, pass the Binja-space address
directly.)

### Step 4 — find `hb_shape_full`

`hb_shapers_lazy_loader_create` runs exactly once on first shaper use. Its
two principal callers are HarfBuzz's main shape entries: `hb_shape_full`
(in `hb-shape.cc`) and `hb_shape_plan_create2` (in `hb-shape-plan.cc`),
both of which fetch the shaper list via `_hb_shapers_get()` which lazily
calls our seed function.

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="hb_shapers_lazy_loader_create",
                       direction="to")
# Typically 2 hits, both in HarfBuzz's own .text region.
```

For each hit, get its parent function and inspect with objdump (convert
Binja addresses back to real VAs):

```bash
START=0x<parent_func_real_va>
objdump -d --start-address=$START --stop-address=$((START + 0x100)) /opt/brave-bin/brave
```

`hb_shape_full` must match **all** of these:

- 5 args (`%rdi`, `%rsi`, `%rdx`, `%ecx`, `%r8` — SysV AMD64 ABI).
- Saves at least 5 callee-saved regs (subset of `%rbp/%rbx/%r12–%r15`); large stack allocation (`sub $0xb0` to `sub $0x110` ish).
- Within the first ~30 instructions: `mov 0x60(%rsi),%eax; test %eax,%eax; je <bail>` — reads `buffer->len`, bails when zero. This is the `if (!buffer->len) return true;` early-out in `hb_shape_full`.
- A few instructions later, clears scratch state: `movw $0x0, 0xd0(%rsi)` (zeroes `allocated_var_bits`+`serial`) **and** `movl $0x0, 0xd8(%rsi)` (zeroes `scratch_flags`). Both must be present together; either one alone could be `_hb_buffer_t::enter()` standalone (also called from many places).
- Big function: hundreds of instructions, many basic blocks. Crude size check: next `int3` padding run is several KB later.

`hb_shape_plan_create2` (the other caller of the lazy loader) takes 5 args
too, but its prologue **lacks the `+0x60` read** because it operates on
shape plans, not buffers. Use the `+0x60` read as the disambiguator.

**Heads-up on clang LTO**: `hb_shape` (a tiny 4-arg wrapper that clears
`%r8` and tail-calls `hb_shape_full`) is usually inlined or fused with
`hb_shape_full` itself. If you find a function that does the `+0x60` read
and the scratch-clear but takes only 4 args (no `r8`), that's the fused
version — still a valid hook target.

Sanity-check by listing the function's own callers:

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="<func_binja_addr>",
                       direction="to")
```

You should see a handful of HarfBuzz-internal callers (real VAs in the
same neighbourhood as `hb_shape_full` itself) **plus** 2–4 callers in
completely different regions of `.text` (Blink and ui/gfx). No "far"
callers → wrong function (probably `_hb_buffer_t::enter()` or
`hb_shape_plan_create2`). Don't assume any particular numeric range for
"far" — Blink and HarfBuzz happen to sit far apart in *this* build, but
that's a layout artifact; the **distinction** that matters is "callers in
the same static-link cluster vs. callers in a totally different region".

Rename, record the **real VA** as `signatures.json:offsets.hb_shape_full`.

### Step 5 — find `hb_buffer_add_utf16` (optional, sanity anchor only)

You can skip this if you only care about getting `capture.js` working
again — `hb_shape_full` is the only address `capture.js` actually uses.
We keep `hb_buffer_add_utf16` in `signatures.json` as a cross-check.

Pick a *far* caller of `hb_shape_full` from Step 4's xrefs (one that
lives outside the HarfBuzz cluster — Blink). Disassemble its containing
function and list every `call`:

```bash
START=0x<blink_caller_func_real_va>
END=0x<blink_caller_func_real_va_plus_size>
objdump -d --start-address=$START --stop-address=$END /opt/brave-bin/brave \
  | grep -E '^\s+[0-9a-f]+:.*\tcall\s'
```

In Blink's `HarfBuzzShaper::GetGlyphData` and `CaseMappingHarfBuzzBufferFiller`
constructor the sequence is roughly:

```
call <hb_buffer_create or wrapper>           ; allocates a buffer
... segment_properties setup ...
call <hb_buffer_add_utf16>                   ; ← the one we want
call <hb_buffer_set_script / set_direction / set_language ...>
call <hb_shape_full>
```

The `call` a few hundred bytes before `hb_shape_full` whose target lands
in the same HarfBuzz neighbourhood as `hb_shape_full` is a strong
candidate. Verify by disassembling the target. `hb_buffer_add_utf16` must
match:

- 5 args.
- Reads byte at `+0x4` of `%rdi` (i.e. `header.writable` — the `hb_object_is_immutable` check) and bails if not `1`. Look for `mov 0x4(%rdi),%al; cmp $0x1,%al; jne ...` near the prologue.
- Compares `%edx` to `-1` AND `%r8d` to `-1` (the `text_length == -1` / `item_length == -1` API sentinels).
- 2-byte-stride pointer arithmetic on `%rsi` somewhere in the body: `lea (%rsi,%rax,2),...` or `movzwl (%rsi,...,2),...`.
- Medium size (a few hundred bytes).

Rename, record the real VA.

### Step 6 — update signatures.json

`signatures.json` has a `_comment` field and a `known_anchors` block —
preserve them. Edit in place; here's the schema with everything filled in:

```json
{
  "_comment": "<keep the existing comment text>",
  "brave_binary": "/opt/brave-bin/brave",
  "brave_build_id": "<paste from readelf -n>",
  "brave_package_version": "<pacman -Q brave-bin / dpkg -l / flatpak info ...>",
  "offsets": {
    "hb_buffer_add_utf16": "0x<real VA from Step 5; null if you skipped it>",
    "hb_shape_full":       "0x<real VA from Step 4>"
  },
  "known_anchors": {
    "HB_SHAPER_LIST_string_va":      "0x<real VA from Step 2>",
    "hb_shapers_lazy_loader_create": "0x<real VA from Step 3>",
    "binja_address_skew":            "0x<your measured skew>"
  }
}
```

### Step 7 — verify end-to-end

```bash
cd ~/devel/opensource/brave-frida-capture
uvx --from frida-tools python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz
```

What to expect within ~30 seconds:

1. stderr: `launching brave (subprocess, no Frida hold)` then `[parent <pid>] brave running`.
2. stderr: `[poll-attach <pid>] renderer detected` plus `[pid <pid>] hooked: {"name":"hb_shape_full",...}` for each renderer that spawns.
3. stdout: lines like `[pid N] From Wikipedia, the free encyclopedia`, `[pid N] Apple Advanced Typography shaping,`, `[pid N] 14.2.0` — **actual text painted on the page.**

Diagnostic table:

| symptom | likely cause | fix |
| --- | --- | --- |
| `hooked:` but no `text` ever | `hb_shape_full` offset points at the wrong function | Re-do Step 4. The +0x60 read alone could match `_hb_buffer_t::enter()`; you need the *combination* of +0x60 read AND `+0xd0`/`+0xd8` clear. |
| `text` lines appear but look like garbage (random short fragments, non-printable codepoints) | `hb_buffer_t` field offsets are wrong (HarfBuzz version changed) | See "When HarfBuzz's struct layout changes" + "Debugging" below. |
| `renderer detected` but no `hooked:` | install errored | grep stderr for `error:` lines from `capture.js`. Most common: brave module not found — see below. |
| `no hook fires` / no `text`, despite `hooked:` log lines | `capture.js` couldn't find the brave module | Confirm `Module.findBaseAddress("brave")` matches a module whose `.path` contains `BRAVE_PATH_HINT` (`/brave-bin/brave`, in `capture.js:17`). If Brave was installed via Flatpak/Snap/non-standard path, update the hint. |
| No `renderer detected` at all after 30s | Brave didn't open a focused window, or didn't open at all | On Wayland: ensure `~/.config/brave-flags.conf` has the right ozone flag (`run.py` reads it automatically). Confirm a Brave window is actually on screen. |
| Frida attach fails with permission error | Linux ptrace restrictions | `cat /proc/sys/kernel/yama/ptrace_scope`; default `1` is fine (we only attach to processes we spawned), but `2` / `3` will block. Don't change kernel settings — this is a hardened-machine signal. |

### Step 8 — commit

```bash
cd ~/devel/opensource/brave-frida-capture
git add signatures.json
git commit -m "Refresh offsets for Brave <version> (build <short-id>)"
```

## When HarfBuzz's struct layout changes

`hb_buffer_t` field offsets are tied to the **vendored HarfBuzz version**,
not the Brave patch version. Check:

```bash
grep '^Version:' /path/to/chromium/src/third_party/harfbuzz-ng/README.chromium
```

If the major still starts with `13.`, the offsets `capture.js` cares about
are stable.

`capture.js` uses three constants you may need to re-derive:

- `BUF_LEN_OFF` — offset of `unsigned int len` in `hb_buffer_t`.
- `BUF_INFO_OFF` — offset of `hb_glyph_info_t *info`.
- `INFO_STRIDE` — `sizeof(hb_glyph_info_t)`. **Compile-time-guaranteed
  20 bytes** by `static_assert (sizeof (hb_glyph_info_t) == 20)` in
  `hb-buffer.h` (around line 211). Stable across HarfBuzz versions as
  long as that assertion is in the source.

To derive new `BUF_LEN_OFF`/`BUF_INFO_OFF`, walk `hb-buffer.hh:struct
hb_buffer_t` from offset 0 with alignment in mind. Or empirically: add
the diagnostic dump from the "Debugging" section, re-run, and verify the
`len` value matches a sensible string length and the `info` pointer
matches the `infoPtr` you read.

### Reference layout (HarfBuzz 13.1.0, x86-64) — only fields capture.js touches

This table is **partial**. The struct continues past `pos` (+0x80) with
`hb_codepoint_t context[2][5]` (40 B), `unsigned context_len[2]` (8 B),
`hb_set_digest_t digest` (24 B = 3 × `uint64_t`), `allocated_var_bits`,
`serial`, `random_state`, `scratch_flags`, `max_len`, `max_ops`, and a
message callback block. Don't read past `+0x80` based on this table —
re-derive from source.

| field | offset | size | notes |
| --- | --- | --- | --- |
| `header.ref_count` | 0x00 | 4 | atomic int |
| `header.writable` | 0x04 | 1 | atomic bool — what `hb_buffer_add_utf16`'s `+0x4` byte read tests |
| (padding) | 0x05 | 3 | aligns next field to 8 |
| `header.user_data` | 0x08 | 8 | atomic ptr |
| `unicode` | 0x10 | 8 | `hb_unicode_funcs_t *` |
| `flags`, `cluster_level` | 0x18, 0x1c | 4, 4 | enums |
| `replacement`, `invisible`, `not_found`, `not_found_variation_selector` | 0x20..0x2f | 4 each | codepoints |
| `content_type` | 0x30 | 4 | enum |
| (padding) | 0x34 | 4 | aligns props (contains an 8-aligned ptr) |
| `props.direction`, `props.script` | 0x38, 0x3c | 4, 4 | |
| `props.language` | 0x40 | 8 | `hb_language_t` (ptr) |
| `props.reserved1`, `props.reserved2` | 0x48, 0x50 | 8 each | |
| `successful`, `have_output`, `have_positions`, (1 pad) | 0x58 | 1+1+1+1 | bools then alignment pad |
| `idx` | 0x5c | 4 | |
| **`len`** | **0x60** | 4 | ← `BUF_LEN_OFF` |
| `out_len`, `allocated` | 0x64, 0x68 | 4 each | |
| (padding) | 0x6c | 4 | aligns next ptr |
| **`info`** | **0x70** | 8 | ← `BUF_INFO_OFF` |
| `out_info`, `pos` | 0x78, 0x80 | 8 each | |

`hb_glyph_info_t` is 20 bytes; `.codepoint` (uint32) at offset 0 holds
the input Unicode codepoint until shaping replaces it with a glyph ID.

## Fallback anchors

If `HB_SHAPER_LIST` isn't findable (extremely unlikely), try in order:

- **HarfBuzz version string** like `"13.1.0"` — referenced from
  `hb_version_string`. Less unique; the version string can appear in
  other contexts. But `hb_version_string` is tiny and recognisable
  (`mov rax, <const ptr>; ret`).
- **Shaper names** in the `_hb_all_shapers` table: pointer-sized entries
  to `"ot"` and `"fallback"` C strings. Find one (likely many xrefs but
  most should land in shaper-iteration code), then the parent of the
  enclosing table is the shapers array, indirectly referenced from
  `hb_shape_list_shapers`.
- **Dynamic symbol leak**: check `nm -D /opt/brave-bin/brave | grep '\<hb_'`.
  Brave currently exports nothing useful here, but a future build or
  different distro packaging might preserve `hb_*` publics. If you see
  any, the workflow becomes trivial — use them by name in capture.js
  via `Module.findExportByName(null, "hb_shape_full")`.

**Don't try `HB_OPTIONS`** — it was an env var in older HarfBuzz; the
current vendored version doesn't read it.

If everything fails, the binary isn't what you think — wrong file,
non-Chromium fork, or HarfBuzz was unbundled and dynamically linked:

```bash
ldd /opt/brave-bin/brave | grep -i harfbuzz
```

If you see a `libharfbuzz.so` entry, hook the `.so` directly in
`capture.js` via `Module.findExportByName("libharfbuzz.so.0", "hb_shape_full")`
and skip the offset hunt entirely.

## Debugging recipes

### Hook fires but output is garbage / empty

The `hb_buffer_t` field offsets are likely wrong. Add a one-shot dump
near the top of the `hb_shape_full` handler in `capture.js`:

```js
function install(opts) {
  // ... existing setup ...
  let dumpedOnce = false;
  installHook('hb_shape_full', offsets.hb_shape_full, function (args) {
    const buffer = args[1];
    if (buffer.isNull()) return;
    let len, infoPtr;
    try {
      len     = buffer.add(BUF_LEN_OFF).readU32();
      infoPtr = buffer.add(BUF_INFO_OFF).readPointer();
    } catch (e) { return; }
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
    // ... rest of existing handler ...
  });
}
```

Re-run against Wikipedia, then `grep '"type": "dump"' /tmp/capture.stderr | head -1`. Check:

- 4 bytes at `+0x60` of `buffer_hex` parsed as little-endian uint32 should match `len`.
- 8 bytes at `+0x70` as little-endian uint64 should match `infoPtr`.
- First 4 bytes of `info0_hex` as LE uint32 should be a reasonable Unicode codepoint (e.g. `50 00 00 00` = U+0050 = `'P'`).

If `len` looks wrong, re-walk `hb-buffer.hh:struct hb_buffer_t` from offset 0 with alignment in mind, update `BUF_LEN_OFF`/`BUF_INFO_OFF`.

### Background tab caveat

Hot loop is foreground tab. `hb_shape_full` calls for offscreen tabs are
*less reliable* but not impossible (`getBoundingClientRect`, intersection
observers, and some layout-only operations can still trigger shaping).
`--new-window` is the right verification setup because it forces a
focused window.

### "I see Chromium font-probe text but nothing real"

If captured strings look like font-coverage probes (`Cwm fjordbank
gly[phs] 😃`, `mmMwWLliI0O&1`), you're running an older `capture.js` that
hooked `hb_buffer_add_utf16` directly. ASCII text goes through
`hb_buffer_add_latin1` which we don't hook; only `hb_shape_full` sees
both paths. Check that the current `capture.js` hooks `hb_shape_full`
and reads codepoints from `buffer->info[].codepoint`.

### MCP keeps timing out

Binja's Python GIL is held by analysis. Either:

- Cancel analysis in Binja (Esc or Tools → Cancel All Background Tasks).
- Use objdump and `tools/find_xref.py` for everything until analysis settles — neither depends on Binja being responsive.
- If the MCP **server** is unresponsive (not just slow), restart the BinAssist plugin on the Binja side, then in Claude Code run `/mcp` to reconnect.

## Reference: end-to-end working example

For Brave `1.89.145-1` (build-id `d6091daa9f05eabe47eb1dcbe13ba40babb32521`):

| symbol | real VA (= file offset for .rodata; .text VA for .text) | how recognised |
| --- | --- | --- |
| `HB_SHAPER_LIST` string | `0x1f22292` | only LEA xref at `0x69df2ae` |
| `hb_shapers_lazy_loader_create` | `0x69df290` | calls `getenv("HB_SHAPER_LIST")` + comma-token parser (`strchr`/`strlen`/`strncmp`) |
| `hb_shape_full` | `0x44c9070` | 5-arg; `mov 0x60(%rsi),%eax; test;je`; then `movw $0,0xd0(%rsi)` + `movl $0,0xd8(%rsi)` |
| `hb_buffer_add_utf16` | `0x44bec70` | 5-arg; reads `0x4(%rdi)` byte (writable check); two `cmp $0xffffffff` sentinels on edx/r8d; `lea (%rsi,%rax,2)` |

Binja MCP address skew for this database: `0x400000` (measured per the
"Critical concept" section above, not assumed).

Buffer field offsets used by `capture.js`: `len` at `+0x60`, `info` at
`+0x70`, `hb_glyph_info_t` stride 20 B, `.codepoint` at offset 0.

Wikipedia verification (`--new-window https://en.wikipedia.org/wiki/HarfBuzz`)
captured 482 unique lines — infobox values (`14.2.0`), sidebar links,
body paragraphs, citation entries — all matching visible page content.
