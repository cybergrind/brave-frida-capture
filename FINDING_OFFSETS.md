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

**Two paths through this workflow:** the steps below are written assuming
Binary Ninja + BinAssist MCP, because that's the original tooling. You can
also run the whole thing with just **objdump, readelf, and the two scripts
in `tools/`** — that path is called out inline as "**No-Binja:**" boxes
under each affected step. The fingerprint heuristics, fallback anchors,
and end-to-end verification are identical either way.

| Tool | Required? | Notes |
| --- | --- | --- |
| **objdump, readelf** | yes | binutils. Used for everything outside Binja so we don't depend on it being responsive. |
| **python3** | yes | stdlib only — `tools/find_xref.py` and `tools/find_callers.py` use no third-party libs. |
| **Chromium source checkout** | yes | Anywhere on disk — we cite paths under `third_party/harfbuzz-ng/src/src/` to interpret disassembly. If you don't have one, [browse vendored HarfBuzz on GitHub](https://github.com/harfbuzz/harfbuzz/tree/main/src) at the matching version. |
| **uv** | yes | Only needed for the final end-to-end verification. Use `uv run python run.py` — **not** `uvx --from frida-tools python run.py`; the latter ignores this project's `requires-python = '>=3.14'` and resolves to an older Python that can't parse `run.py`'s PEP 758 `except` syntax. |
| **Binary Ninja** | optional | Commercial edition (Personal forbids the plugin model BinAssist uses). Open `/opt/brave-bin/brave` and let analysis start — it doesn't have to be complete; we force it on demand below. The analysis DB in MCP is typically named `brave.bndb`; confirm with `mcp__binassist__list_binaries`. Skip if you're using the No-Binja path. |
| **BinAssist MCP plugin** | optional | Only needed with Binja. Reachable at `http://localhost:8000/mcp`. `curl -X POST -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' http://localhost:8000/mcp` should return 200 in under 1s. Registered in `~/.claude.json` as `binassist`. **If you restart the MCP server, run `/mcp` in Claude Code to reconnect** — the old session ID is otherwise invalid and calls return `Bad Request: No valid session ID provided`. |

`tools/`:
- `find_xref.py <va>` — scans `.text` for RIP-relative `LEA` instructions
  pointing at `<va>`. Use to xref *to a string or data symbol*. Self-configures
  from PT_LOAD; no per-build constants.
- `find_callers.py <va>` — scans `.text` for direct `CALL` (and optionally
  `JMP`) sites whose rel32 target equals `<va>`. Use to xref *to a function
  start* — i.e. as a Binja-free substitute for `xrefs(direction='to')`.

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

**No-Binja path** (also the cross-check for Binja users):

```bash
strings -t x /opt/brave-bin/brave | grep -F 'HB_SHAPER_LIST'
# → e.g. "1f22292 HB_SHAPER_LIST" — that hex is the real VA.
```

(`HB_SHAPER_LIST` lives in `.rodata`, which is in the *first* PT_LOAD where
`p_offset == p_vaddr`, so strings(1)'s file offset equals the real VA.)

**Via Binja MCP:**

```text
mcp__binassist__search_strings(filename="brave.bndb", pattern="HB_SHAPER_LIST")
```

Note Binja's reported address; the real VA is that minus your skew.

If neither route returns a hit, see "Fallback anchors" below.

### Step 3 — find the lazy-loader function (the seed function)

The only xref to `HB_SHAPER_LIST` is a `lea ..., [rip+disp]` loading its
address into `%rdi` before `call getenv@plt`. The enclosing function is
`hb_shapers_lazy_loader_t::create` — the lazy `create()` method of the
shapers loader. (Older HarfBuzz had a separate `hb_options_init` function;
that's gone. Don't expect to find a symbol by that name.)

**No-Binja path** (also more reliable than Binja when its analysis is
still mid-flight): scan `.text` for the LEA that loads the string's
address. The scanner reads `.text` bounds from the ELF, so no per-build
constants:

```bash
python3 tools/find_xref.py 0x<real_VA_of_HB_SHAPER_LIST>
# → prints each matching LEA's real VA; expect exactly 1 hit
```

**Via Binja MCP** (Binja-space addresses):

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="<HB_SHAPER_LIST_binja_addr>",
                       direction="to")
# Expect 1 hit. Take its `address`, pass to:
mcp__binassist__get_parent_function(filename="brave.bndb",
                                     address="<the xref address>")
# → records the function start in Binja-space
```

(If Binja reports `function: null` or `get_parent_function` times out
because analysis hasn't reached that region, fall back to `find_xref.py`
above — that's why we keep it.)

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
objdump -d --start-address=$((HIT - 0x800)) --stop-address=$((HIT + 0x40)) /opt/brave-bin/brave \
  | grep -B1 -E '^\s*[0-9a-f]+:\s+cc\s+' | tail -20
# The first instruction *after* the trailing `cc` run is the function start.
# Cross-check that it's a `push %rbp` or `endbr64; push %rbp` prologue:
objdump -d --start-address=0x<candidate_start> --stop-address=0x<candidate_start+0x20> /opt/brave-bin/brave
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

Record the function's real VA — Step 4 needs it.

**Binja users:** rename it for convenience (lets Step 4 use the name in
xref queries instead of the Binja-space address):

```text
mcp__binassist__rename_symbol(filename="brave.bndb",
                               address_or_name="<func_start_binja_addr>",
                               new_name="hb_shapers_lazy_loader_create")
```

(Renaming is optional. If you skip it, pass the Binja-space address
directly in Step 4's xref query.)

### Step 4 — find `hb_shape_full`

`hb_shapers_lazy_loader_create` runs exactly once on first shaper use. Its
two principal callers are HarfBuzz's main shape entries: `hb_shape_full`
(in `hb-shape.cc`) and `hb_shape_plan_create2` (in `hb-shape-plan.cc`),
both of which fetch the shaper list via `_hb_shapers_get()` which lazily
calls our seed function.

**No-Binja path:** scan `.text` for direct `CALL` instructions whose
rel32 target equals `hb_shapers_lazy_loader_create`'s real VA:

```bash
python3 tools/find_callers.py 0x<lazy_loader_real_va>
# Typically 2 hits, both in HarfBuzz's own .text region.
# Each printed VA is the call-site, not the enclosing function start —
# walk backward the same way Step 3 did:
HIT=0x<call_site_va>
objdump -d --start-address=$((HIT - 0x800)) --stop-address=$((HIT + 0x40)) /opt/brave-bin/brave \
  | grep -B1 -E '^\s*[0-9a-f]+:\s+cc\s+' | tail -20
# First instruction after the trailing `cc` run = parent function's start.
```

If `find_callers.py` shows 0 or 1 hits, retry with `--include-jmp` — clang
sometimes emits a tail-call `JMP rel32` for one of the two callers.

**Via Binja MCP** (Binja-space addresses):

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="hb_shapers_lazy_loader_create",
                       direction="to")
# Typically 2 hits. Each has a `function` field with the enclosing function's
# start address in Binja-space — convert back to real VA by subtracting skew.
```

For each candidate parent function, inspect the prologue with objdump:

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

Sanity-check by listing the function's own callers.

**No-Binja path:**

```bash
python3 tools/find_callers.py 0x<candidate_func_real_va>
```

**Via Binja MCP:**

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="<func_binja_addr>",
                       direction="to")
```

Either way you should see a handful of HarfBuzz-internal callers (real
VAs in the same neighbourhood as `hb_shape_full` itself) **plus** 2–4
callers in completely different regions of `.text` (Blink and ui/gfx).
No "far" callers → wrong function (probably `_hb_buffer_t::enter()` or
`hb_shape_plan_create2`). Don't assume any particular numeric range for
"far" — Blink and HarfBuzz happen to sit far apart in *this* build, but
that's a layout artifact; the **distinction** that matters is "callers
in the same static-link cluster vs. callers in a totally different
region".

Record the **real VA** as `signatures.json:offsets.hb_shape_full`.
(Binja users: optionally rename for clarity in future sessions.)

### Step 5 — find `hb_buffer_add_utf16` (optional, sanity anchor only)

You can skip this if you only care about getting `capture.js` working
again — `hb_shape_full` is the only address `capture.js` actually uses.
We keep `hb_buffer_add_utf16` in `signatures.json` as a cross-check.

Pick a *far* caller of `hb_shape_full` from Step 4's xrefs (one that
lives outside the HarfBuzz cluster — Blink). Each xref VA is a call-site,
not a function start; resolve it back to its enclosing function the same
way Step 3/4 did (walk backward to the last `cc`-padding run):

```bash
HIT=0x<blink_call_site_va>
objdump -d --start-address=$((HIT - 0x1000)) --stop-address=$((HIT + 0x40)) /opt/brave-bin/brave \
  | grep -B1 -E '^\s*[0-9a-f]+:\s+cc\s+' | tail -20
# First instruction after the trailing `cc` = Blink caller function start.
```

Then list every `call` in that function (use a generous size; Blink
shapers are several KB):

```bash
START=0x<blink_caller_func_real_va>
END=$((START + 0x2000))
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

Edit `signatures.json` in place. Only `offsets.hb_shape_full` is read at
runtime; everything else is documentation. Schema (omit any `known_anchors`
entry you didn't capture — they're informational, not required):

```json
{
  "_comment": "<keep / refresh comment if stale; pointer to FINDING_OFFSETS.md is canonical>",
  "brave_binary": "/opt/brave-bin/brave",
  "brave_build_id": "<paste from readelf -n>",
  "brave_package_version": "<pacman -Q brave-bin / dpkg -l / flatpak info ...>",
  "offsets": {
    "hb_buffer_add_utf16": "0x<real VA from Step 5; omit if skipped>",
    "hb_shape_full":       "0x<real VA from Step 4>"
  },
  "known_anchors": {
    "HB_SHAPER_LIST_string_va":      "0x<real VA from Step 2>",
    "hb_shapers_lazy_loader_create": "0x<real VA from Step 3>",
    "binja_address_skew":            "0x<your measured skew — omit on No-Binja path>"
  }
}
```

### Step 7 — verify end-to-end

```bash
cd ~/devel/opensource/brave-frida-capture
# Pre-flight: catch any syntax error in run.py before launching Brave.
uv run python -m py_compile run.py
# End-to-end run (use timeout to cap; exit 124 = our timeout firing, not a failure):
timeout 50 uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz
```

**Use `uv run`, not `uvx --from frida-tools`.** `uvx` runs in the
frida-tools tool environment, whose Python may not satisfy this project's
`requires-python` pin (currently `>=3.14`) — `run.py` uses PEP 758
unparenthesized `except` syntax that Python 3.13 rejects with
`SyntaxError`. `uv run` uses our `.venv`, which has the right Python.

What to expect within ~30 seconds:

1. stderr: `launching brave (subprocess, no Frida hold)` then `[parent <pid>] brave running`.
2. stderr: `[poll-attach <pid>] renderer detected` plus `[pid <pid>] hooked: {"name":"hb_shape_full",...}` for each renderer that spawns.
3. stderr (one-shot per renderer): `[pid <pid>] msg: {'type': 'dump', 'len': <n>, 'info0_hex': '<4 bytes of codepoint> ...'}` — `capture.js` emits a single layout-health dump per process. The first 4 bytes of `info0_hex` as LE uint32 must decode to a reasonable Unicode codepoint (e.g. `53 00 00 00` = `'S'`, `50 00 00 00` = `'P'`). If it doesn't, see "Hook fires but output is garbage" below.
4. stdout: lines like `[pid N] From Wikipedia, the free encyclopedia`, `[pid N] Apple Advanced Typography shaping,` — **actual text painted on the page.** A healthy Wikipedia run captures ~1400+ lines.

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

## Phase 6 anchors: `paint_op_with_flags_RasterWithFlags` + DrawTextBlobOp x/y

The Phase 6 hook needs ONE address in `/opt/brave-bin/brave` (the
dispatcher) and TWO struct offsets (`op->x`, `op->y`) inside
DrawTextBlobOp. They're recorded under `offsets:` in `signatures.json` as
`paint_op_with_flags_RasterWithFlags`, `draw_text_blob_op_x_offset`, and
`draw_text_blob_op_y_offset` (defaults `0x78` / `0x7c`).

The dispatcher fires in **every process that does cc::PaintOp playback**.
In Brave 1.90.122-1 with default flags that includes both renderers
(one per tab; Brave's site-isolation keeps them separate) and the
gpu-process. Empirical signature in a multi-tab capture: each renderer
pid emits both `text` (from `hb_shape_full`) and `draw_text` (from
this dispatcher); the gpu-process emits only `draw_rect` via the
SkCanvas catch-all. `run.py` and `capture.js` accept both
`--type=renderer` and `--type=gpu-process` and install the dispatcher
hook in whichever process is attached.

(Earlier notes in this repo claimed gpu-process only — that was
incorrect; corrected after observing a 4-pid capture where 3 renderer
pids each carried independent text+draw_text streams.)

### Refresh workflow

#### Step P1 — find the dispatcher

Seed anchor: the literal string `"DisplayItemList::Raster"` (ASCII, in
`.rodata`).

```bash
strings -t x /opt/brave-bin/brave | grep -F 'DisplayItemList::Raster'
# → e.g. "1bad17c DisplayItemList::Raster" — real VA
```

There's exactly one xref to that string inside
`cc::DisplayItemList::Raster`. That function calls
`cc::PaintOpBuffer::Playback`, which calls
`cc::PaintOpWithFlags::RasterWithFlags` (the dispatcher we want). With
Binja:

```text
mcp__binassist__xrefs(filename="brave.bndb",
                       address_or_name="0x<DisplayItemList_Raster_string_binja_addr>",
                       direction="to")
mcp__binassist__get_parent_function(filename="brave.bndb",
                                     address="<one xref>")
# → cc::DisplayItemList::Raster
mcp__binassist__get_code(filename="brave.bndb",
                          function_name_or_address="<that addr>",
                          format="decompile")
# → look for a `sub_XXXXXX(rdi, &flags, &canvas)` near a `cmp 0x60 / + 0x68` check;
# that callee is PaintOpBuffer::Playback (similar internal structure).
```

`PaintOpBuffer::Playback` in turn dispatches to the dispatcher via the
`flags_op.RasterWithFlags` call. The dispatcher's fingerprint is:

- 4 args (`%rdi=op`, `%rsi=flags`, `%rdx=canvas`, `%rcx=params`).
- Reads `op->type` as `movzx ecx, byte [rdi]` near the prologue.
- Compares against `kNumOpTypes` (`cmp $0x24,%rcx; jae <trap>`).
- Loads a function-pointer table with `lea rax, [rel <data.rel.ro addr>]; mov rax, [rax+rcx*8]`.
- Has explicit inlined cases for hot types — at minimum `cmp $0x12, %rcx; je <kDrawRect>` and `cmp $0x17, %ecx; je <kDrawTextBlob>` (0x12=18, 0x17=23).

**No-Binja path:** scan `.text` for the prologue pattern + jump-table
indirection. Easiest: grep objdump for `cmp $0x24,%rcx` and pick the hit
where the next dozen instructions match the fingerprint above.

```bash
objdump -d /opt/brave-bin/brave 2>/dev/null \
  | awk '/cmp\s+\$0x24,%rcx/{p=NR; print}' \
  | head -5
```

Take any hit, then `objdump -d --start-address=<HIT - 0x40> --stop-address=<HIT + 0x80>` and walk backward over `cc` padding to the function prologue (`push %rbp; mov %rsp,%rbp; push %r15; ...`). Verify the inlined case structure (`movss 0x78(%r14), %xmm0` somewhere in the kDrawTextBlob branch — see step P2).

Record the dispatcher's real VA as
`offsets.paint_op_with_flags_RasterWithFlags`.

#### Step P2 — verify DrawTextBlobOp x/y offsets

Inside the dispatcher, find the kDrawTextBlob inlined case (reached
from the `cmp $0x17, %ecx; je <case>` at a few-byte offset from the
function start). Disassemble there; the case body must contain, in
order:

```
mov  0x80(%rNN),%esi             ; op->node_id check
cmp  0x70(%rNN),... or similar   ; params.is_analyzing check (offset 0x70 into params)
mov  0x50(%rNN),%rsi             ; op->blob.get()
movss 0x78(%rNN),%xmm0           ; op->x  ← record this offset
movss 0x7c(%rNN),%xmm1           ; op->y  ← record this offset
call <SkCanvas::drawTextBlob>
```

If `op->x` / `op->y` land at offsets other than `0x78` / `0x7c`, update
`draw_text_blob_op_{x,y}_offset` accordingly. They've been stable since
the field layout `blob; slug; extra_slugs; x; y; node_id` got
established in cc/paint/paint_op.h.

The kNumOpTypes value (currently 36) and the kDrawSlug / kDrawTextBlob
enum indices (22 / 23) come from `cc/paint/paint_op.h:85` — bump
them if Chromium adds new enum variants.

#### Step P3 — verify in a live process

Either re-run end-to-end (`uv run python run.py -- --new-window
https://en.wikipedia.org/wiki/HarfBuzz` and check that `draw_text
DrawTextBlob x=<positive> y=<positive>` lines appear in stdout), or
attach Frida ad-hoc to any attached process (renderer or gpu-process —
see the dispatcher-fires-everywhere note above) and read 16 bytes at
the op address printed by the hook to confirm x/y look like sane pixel
floats.

If you're verifying with the multi-tab capture flow + `render_ascii.py
--list-pids`, you'll see one pid per tab carrying both `text` and
`draw_text` records, plus a separate pid carrying only `draw_rect`
records. That separate pid is the gpu-process; the others are
renderers. Either category is a valid place to read DrawTextBlobOp
fields from.

## Phase 7 anchors: filled-rectangle capture

Phase 7 (`draw_rect` events) needs three groups of offsets in
`signatures.json:offsets`:

- The PaintOpType enum indices `paint_op_kDrawRect` / `kDrawRRect` /
  `kDrawIRect` / `kDrawOval` (currently 18 / 19 / 12 / 15). Bump only if
  Chromium adds new enum variants — see `cc/paint/paint_op.h:85`.
- Geometry field offsets `draw_rect_op_rect_offset` etc., all `0x50`
  in Brave 1.90.122-1. Stable as long as `sizeof(PaintOpWithFlags)` doesn't
  change (see § "Why 0x50" below).
- Function addresses for the per-op static rasterizers
  (`draw_rect_op_RasterWithFlags` etc.) and `SkCanvas::drawRect`.

### Why 0x50

`PaintOpWithFlagsBaseInternal` is `PaintOp` (uint8 `type` at +0, 7 B padding
to align-8) + `PaintFlags`. `PaintFlags` inherits `CorePaintFlags`:

| field | offset | size | notes |
| --- | --- | --- | --- |
| `color_` | +0x00 | 16 | SkColor4f (4 f32: R, G, B, A) |
| `width_` | +0x10 | 4 | f32 stroke width |
| `miter_limit_` | +0x14 | 4 | f32 |
| `bitfields_` | +0x18 | 4 | packed flags / blend mode |
| (padding to align-8) | +0x1c | 4 | |
| `targeted_hdr_headroom_` (PaintFlags) | +0x20 | 4 | f32 |
| (padding to align-8) | +0x24 | 4 | |
| 5 × `sk_sp<>` (path_effect_, shader_, color_filter_, draw_looper_, image_filter_) | +0x28 | 8 each | |

Total CorePaintFlags + PaintFlags = 0x48. Plus the 8-byte `PaintOp` header
yields **0x50**, which is where the first derived-class member (e.g.
`DrawRectOp.rect`, `DrawTextBlobOp.blob`) sits.

Verified by disassembling the kDrawRect inlined case in the dispatcher
(loads `(%r15)` = `color_` from flags, then later `0x10(%r15)` = width,
`0x14(%r15)` = miter, `0x18(%r15)` = bitfields, …), and by the
`add $0x50,%r14` in every per-op `RasterWithFlags` immediately before the
SkCanvas call.

### Refresh workflow

#### Step P4 — locate the per-op RasterWithFlags table

The four per-op functions are referenced from the
`g_raster_with_flags_functions` array at known anchor
`0x11a5ed20` (real VA, from Phase 6). Each slot is an 8-byte relative
relocation pointing at a 5-byte `jmp rel32` stub, which tail-calls the
actual function body.

```bash
# kDrawRect=18 → table base + 18*8 = +0x90 → slot at 11a5edb0
# kDrawRRect=19 → +0x98 → slot at 11a5edb8
# kDrawIRect=12 → +0x60 → slot at 11a5ed80
# kDrawOval=15  → +0x78 → slot at 11a5ed98
readelf -r /opt/brave-bin/brave 2>/dev/null \
  | grep -E "11a5ed(80|98|b0|b8)\b"
```

You'll see four `R_X86_64_RELATIVE` entries pointing at jmp-stubs in the
`malloc_size@@Base+…` region (currently `0x6fe96b0` / `c8` / `e0` / `e8`).
Disassemble each stub to read the real target:

```bash
objdump -d --start-address=0x<stub_va> --stop-address=$((0x<stub_va> + 16)) /opt/brave-bin/brave
# → `jmp rel32 <target>` — target is the per-op RasterWithFlags entry
```

Record each target as `draw_<kind>_op_RasterWithFlags` in
`signatures.json:offsets`.

**Verification:** disassemble each function body and confirm:
- 4-arg signature (`rdi=op, rsi=flags, rdx=canvas, rcx=params`).
- Allocates an SkPaint on the stack with `xorps + movaps` zeroing,
  then `call <PaintFlags::DrawToSk> or <SkPaint ctor helper>`.
- `add $0x50,%r14` (or `+0x50,%rNN` depending on which register
  holds `op`) somewhere in the body, then `mov %rNN, %rsi` and
  `call <SkCanvas::draw*>`.
- For DrawIRect: extra `movups 0x50(%rNN), %xmm0; cvtdq2ps` (loads
  4 int32, converts to floats) before the drawRect call.

#### Step P5 — locate SkCanvas::drawRect

SkCanvas::drawRect is the primary catch-all hook for filled rects (most
PaintOpBuffer::Playback rect ops get LTO-inlined past the per-op
RasterWithFlags entries; SkCanvas::drawRect catches everything that lands
in Skia). It's reached from the inlined kDrawRect case in the dispatcher:

```bash
# Disassemble PaintOpWithFlags::RasterWithFlags around the kDrawRect inlined
# branch (start ≈ dispatcher_va + 0x180), look for the final 5-byte rel32 call
# right after `add $0x50,%r14` + `mov %r14, %rsi`:
objdump -d --start-address=$((0x<dispatcher_va> + 0x180)) \
             --stop-address=$((0x<dispatcher_va> + 0x420)) /opt/brave-bin/brave \
  | grep -E "add\s+\\\$0x50,%r14" -A2 | head -10
# That `call rel32` target = SkCanvas::drawRect's real VA.
```

Verify the function: large (>0x300 B), saves r12-r15+rbx, reads
`movsd (%r15)` (loads 8 bytes from rsi=&rect) early in the body.

#### Step P6 — verify end-to-end

After updating `signatures.json:offsets`, run:

```bash
uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz
```

Expect:
- `hooked` lines for all of: `hb_shape_full`,
  `PaintOpWithFlags::RasterWithFlags`, the four per-op
  `Draw*Op::RasterWithFlags`, and `SkCanvas::drawRect`.
- Hundreds of `draw_rect SkRect …` records with `l`, `t`, `r`, `b` floats
  in a sane viewport range (e.g. `0..1300`).
- A handful of `draw_rect DrawIRect`/`DrawRect`/`DrawRRect`/`DrawOval`
  records with `color=#rrggbbaa` strings.
- Existing `text` and `draw_text` records still flowing.

## Phase 8 anchors: SkCanvas CTM read path

Phase 8 emits screen-absolute `(sx, sy)` (and `sleft/stop/sright/sbottom`)
alongside the layer-local coords by reading SkCanvas's current matrix at
hook entry. It needs two struct offsets, both pinned in
`signatures.json:offsets`:

- `sk_canvas_mcrec_offset` — offset of `MCRec* SkCanvas::fMCRec`. In Brave
  1.90.122-1: `0x640`.
- `mcrec_matrix_offset` — offset of `SkM44 MCRec::fMatrix` within the
  MCRec record. In Brave 1.90.122-1: `0x18` (after `fLayer`,
  `fDevice`, `fBackImage` — three 8-byte pointers).

Matrix kind is `SkM44`: 16 little-endian f32 in **column-major** layout,
i.e. `fMat[c*4 + r] = m(r,c)`. For a 2D affine the consumer only needs
`sx = m00·x + m01·y + m03` and `sy = m10·x + m11·y + m13`, which in
SkM44 storage is `fMat[0]*x + fMat[4]*y + fMat[12]` and
`fMat[1]*x + fMat[5]*y + fMat[13]`.

### Refresh workflow

Both offsets are stable for as long as Chromium-vendored Skia keeps the
declaration order of `SkCanvas::fMCRecStorage / fMCStack / fMCRec` (see
`include/core/SkCanvas.h`) and `MCRec::fLayer / fDevice / fBackImage /
fMatrix` (same file). Refresh when:

- `signatures.json:brave_build_id` no longer matches and the hooks
  are reporting `draw_text` with sx/sy that look obviously wrong (NaN,
  enormous magnitudes, or identical to x/y everywhere despite obvious
  transform layers).
- A new run shows `sx == x` and `sy == y` for *every* record (CTM read
  is silently failing — either fMCRec offset is stale and dereferences
  to garbage that null-checks pass but produces a zero / identity
  matrix at offset +0x18, or it's null and `readCTM` returns null).

#### Step P7 — verify the SkCanvas layout

The reliable way to confirm both offsets in a fresh build is to
disassemble a SkCanvas method that emits the matrix-load pattern. Two
candidates known to work:

- `SkCanvas::drawRect` — find its real VA via the Phase 7 workflow
  (already an anchor in `signatures.json`).
- `SkCanvas::drawTextBlob` — similar; anchor `SkCanvas_drawTextBlob`.

Both functions, near the start of the call-into-Skia code path, emit:

```
mov 0x<SK_CANVAS_MCREC_OFF>(<this_reg>), %r<NN>
add $0x<MCREC_MATRIX_OFF>, %r<NN>
lea -0x<stack_offset>(%rbp), %rsi
call <SkM44::mapRect>           ; ~+0x7000 forward in the same .text region
```

In Brave 1.90.122-1 the disassembly at `SkCanvas::drawRect+0x144`:

```
3f715b4: mov  0x640(%rbx),%rdi
3f715bb: add  $0x18,%rdi
3f715bf: lea  -0xb0(%rbp),%rsi
3f715c6: call 3f6ebd0           ; SkM44::mapRect
```

`%rbx` holds `this` (loaded from `%rdi` at function entry). The
`0x640` is `SK_CANVAS_MCREC_OFF`; the `0x18` is `MCREC_MATRIX_OFF`.

Same sequence appears in `SkCanvas::drawTextBlob+0x376` and again
`+0x4d3` with `%r13` instead of `%rbx`.

To find the pattern in a new build:

```bash
# Find candidate hits inside SkCanvas::drawRect:
objdump -d --start-address=0x<SkCanvas_drawRect_va> \
             --stop-address=$((0x<SkCanvas_drawRect_va> + 0x800)) \
             /opt/brave-bin/brave \
  | grep -B1 -A2 -E 'mov\s+0x[0-9a-f]+\(%r[a-z0-9]+\),%r[a-z0-9]+' \
  | grep -A2 'add\s+\$0x[0-9a-f]+,'
```

You want the unique `mov 0xN(thisreg), %rN; add $0xM, %rN` pair where
`%rN` then becomes the `this` arg of a tight `call rel32` a few bytes
later (the `SkM44::mapRect` invocation). `N` is `SK_CANVAS_MCREC_OFF`;
`M` is `MCREC_MATRIX_OFF`.

#### Step P8 — verify at runtime

After updating `signatures.json:offsets.sk_canvas_mcrec_offset` and
`mcrec_matrix_offset`, run end-to-end:

```bash
uv run python run.py -- --new-window https://en.wikipedia.org/wiki/HarfBuzz
```

Healthy output:

- Each `draw_text DrawTextBlob` line carries `sx=... sy=...` followed
  by `(x=... y=...)`.
- For top chrome / nav (no CSS transforms), `sx ≈ x` and `sy ≈ y`.
- For sub-layers (sticky headers, table-of-contents widget, scrolling
  containers), `sx`/`sy` differ from `x`/`y` by the layer's screen
  offset — e.g. `sl=19 st=10 sr=267 sb=51 (l=0 t=0 r=248 b=41)`
  reveals a translation layer at (19, 10) on screen.
- Scroll the page (PgDown). Records that re-paint after scrolling show
  the same `(x,y)` mapping to a smaller `sy` than before — the
  CTM translation tracks scroll position.

Failure modes:

- All `sx == x` and `sy == y`: `MCRec*` dereferences to a NULL or to
  a struct where `+MCREC_MATRIX_OFF` happens to contain the identity.
  Re-derive both offsets via Step P7. The Skia upstream layout shouldn't
  have shifted — if it has, also check `MCRec::fBackImage` (might have
  grown / shrunk and shoved fMatrix forward or back).
- `sx/sy` are NaN or enormous (10⁸+): `fMCRec` offset is reading
  arbitrary memory; double-check `0x640` against your build.
- `sx == x` only for some records: those hooks may be reading the
  wrong register as `canvas`. Verify the args[] indices in
  `capture.js:installPaintOpHooks` against the disassembly of the
  hooked function.

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
- Use objdump, `tools/find_xref.py`, and `tools/find_callers.py` for everything until analysis settles — none of these depend on Binja being responsive. The "No-Binja path" boxes under each step cover the same operations.
- If the MCP **server** is unresponsive (not just slow), restart the BinAssist plugin on the Binja side, then in Claude Code run `/mcp` to reconnect.

## Reference: two end-to-end working examples

Two builds shown side-by-side so future agents can see how VAs move while
the fingerprints don't. Current authoritative values live in
[CLAUDE.md § Confirmed anchors](./CLAUDE.md#confirmed-anchors-real-vas-for-brave-190122-1)
and `signatures.json`; the tables below are historical reference.

### Brave 1.89.145-1 (build-id `d6091daa…`) — Binja-MCP path

| symbol | real VA | how recognised |
| --- | --- | --- |
| `HB_SHAPER_LIST` string | `0x1f22292` | only LEA xref at `0x69df2ae` |
| `hb_shapers_lazy_loader_create` | `0x69df290` | calls `getenv("HB_SHAPER_LIST")` + comma-token parser (`strchr`/`strlen`/`strncmp`) |
| `hb_shape_full` | `0x44c9070` | 5-arg; `mov 0x60(%rsi),%eax; test;je`; then `movw $0,0xd0(%rsi)` + `movl $0,0xd8(%rsi)` |
| `hb_buffer_add_utf16` | `0x44bec70` | 5-arg; reads `0x4(%rdi)` byte (writable check); two `cmp $0xffffffff` sentinels on edx/r8d; `lea (%rsi,%rax,2)` |

`.text` VA `0x322b000`. Binja MCP address skew: `0x400000` (measured).
Wikipedia verification captured 482 unique lines.

### Brave 1.90.122-1 (build-id `854f18fa…`) — No-Binja path

| symbol | real VA | how recognised |
| --- | --- | --- |
| `HB_SHAPER_LIST` string | `0x1e88556` | `strings -t x \| grep`, 1 hit |
| `hb_shapers_lazy_loader_create` | `0x69c6000` | `find_xref.py 0x1e88556` → 1 hit at `0x69c601e`; walked back over `cc` padding to prologue; calls `getenv@plt` then `__libc_memalign+0x10` (the hb_calloc shim) then `strchr`/`strlen`/`strncmp` |
| `hb_shape_full` | `0x46876c0` | `find_callers.py 0x69c6000` → 2 hits (`0x4687e2e`, `0x46943c1`). Candidate 1 prologue: 5-arg, `sub $0xb8,%rsp`, `mov 0x60(%rsi),%eax;test;je`, `movw $0,0xd0(%rsi)` + `movl $0,0xd8(%rsi)`. Candidate 2 was `hb_shape_plan_create2` (LEA + test rsi, no `+0x60` read) |
| `hb_buffer_add_utf16` | `0x4682850` | `find_callers.py 0x46876c0` → 4 hits (2 internal, 2 far). Walked back from far hit `0xe0f04e2` to Blink caller `0xe0f0380`. Call at `0xe0f0483` targets `0x4682850`; fingerprint matched: `+0x4` writable check, `cmp $-1` on edx and r8d, `lea (%rsi,%rax,2)`, `movzwl` reads |

`.text` VA `0x3222000` (note: **shifted from `0x322b000`** in prior build —
absolute numbers are not stable across releases; only the fingerprints
are). No Binja used → no skew.

Buffer field offsets in `capture.js` were **unchanged**: `len` at `+0x60`,
`info` at `+0x70`, `hb_glyph_info_t` stride 20 B, `.codepoint` at offset 0.
The one-shot dump from `capture.js` confirmed `info0_hex` starts
`53 00 00 00` (`'S'`) — visible on Wikipedia's "Search" button.

Wikipedia verification: ~1400 unique lines, including page body
("`shaper handles the majority of scripts`", "`Apple Advanced
Typography`", "`GNOME libraries`"), nav (Search, Donate, Log in), and
sidebar metadata — all matching visible content.
