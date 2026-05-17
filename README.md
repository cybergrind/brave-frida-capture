# brave-frida-capture

Capture every Unicode string Brave shapes for the screen, by hooking HarfBuzz
inside each renderer process with Frida.

> Research / instrumentation tool. Requires `--no-sandbox`, so don't browse with
> the spawned instance. Persistent profile lives in
> `~/.config/BraveSoftware/brave-frida/`.

For context on *why* it works this way, why we don't just use CDP, and how to
reason about the codebase if you're picking this up cold, read
[CLAUDE.md](./CLAUDE.md) first and then [PLAN.md](./PLAN.md).

## What it does

Hooks `hb_shape_full` in every renderer process and prints each unique string
Blink shapes for the screen. At `hb_shape_full` entry the input text sits in
the `hb_buffer_t`'s `info[]` array (one Unicode codepoint per slot in the
first 4 bytes); the agent reads the buffer and reconstructs the string.

Why `hb_shape_full` rather than the more obvious `hb_buffer_add_utf16`:
Blink calls `hb_buffer_add_latin1` for ASCII text (the majority of web
content) and only uses `hb_buffer_add_utf16` for strings containing non-Latin-1
codepoints. Hooking `hb_shape_full` catches both paths from a single point.

## Prerequisites

- Linux x86-64
- Brave installed at `/opt/brave-bin/brave` (Arch `brave-bin` package). Other
  paths work with `--brave /path/to/brave`.
- [`uv`](https://github.com/astral-sh/uv); `uv sync` to install the
  frida-tools environment declared in `pyproject.toml`.
- `~/.config/BraveSoftware/brave-frida/` will be created on first run. The
  profile **persists across runs**.
- A `signatures.json` with non-null offsets for `hb_buffer_add_utf16` (see
  "Finding offsets" below). Without offsets the agent loads but skips hooking.

## Run

```bash
cd ~/devel/opensource/brave-frida-capture
uv run python run.py
```

Output on stdout is one captured string per line:

```
[pid 124091] Hello, world
[pid 124091] Search Wikipedia
[pid 124091] Read the article
```

Frida bookkeeping (process attach, hook installation, errors) goes to stderr.

Pass extra args through to Brave after `--`:

```bash
uv run python run.py -- https://en.wikipedia.org/wiki/HarfBuzz
```

Stop with `Ctrl-C`. The Brave subprocess is killed; the profile stays.

## Finding offsets

`signatures.json` is the binding between `capture.js` and a specific Brave
build. It looks like:

```json
{
  "brave_build_id": "d6091daa9f05eabe47eb1dcbe13ba40babb32521",
  "offsets": {
    "hb_buffer_add_utf16": "0x...",
    "hb_shape_full": "0x..."
  }
}
```

Offsets are file offsets relative to the start of `/opt/brave-bin/brave`
(which equals the runtime VA — the binary is mapped 1:1 in the first
PT_LOAD). At runtime the agent uses
`Module.findBaseAddress("brave").add(offset)`.

### When you'll need to refresh

- Brave was updated. Check `readelf -n /opt/brave-bin/brave` and compare
  build-id against the one in `signatures.json`. Mismatch → re-find.
- You switched to a different Brave channel or self-built Brave.

### Finding offsets, the workflow

Two viable approaches; pick by what's installed locally.

#### A. Binary Ninja + BinAssist MCP (what we did)

1. Open `/opt/brave-bin/brave` in Binja and let analysis run. **Heads up: the
   binary is ~283 MB; full analysis can take a long time and will lock the MCP
   server while running.** You can use partial analysis — just be ready to
   re-trigger function analysis on specific addresses.
2. Connect Binja MCP (BinAssist) so a Claude session can drive it.
3. Find `HB_SHAPER_LIST` in Strings; the only xref is inside
   `hb_options_init`. Rename it.
4. From `hb_options_init`, browse neighboring functions — HarfBuzz code is one
   contiguous static-link cluster. Identify `hb_buffer_add_utf16` and
   `hb_shape_full` by argument count (5) and structural traits described in
   [PLAN.md](./PLAN.md).
5. **Subtract `0x400000`** from every address Binja returns — Binja MCP
   reports addresses with a +0x400000 analysis base offset. The actual VA
   matches the file offset for this binary.
6. Edit `signatures.json` with the corrected offsets.

#### B. Standalone scanner against a chromium-built reference

1. Build chromium-vendored HarfBuzz with chromium's toolchain:
   ```
   third_party/llvm-build/Release+Asserts/bin/clang++ -O2 ... \
       third_party/harfbuzz-ng/src/src/*.cc
   ```
2. Dump bytes of `hb_buffer_add_utf16` and `hb_shape_full` from the resulting
   object file (`objdump -d --disassemble=hb_buffer_add_utf16`).
3. Run `tools/find_xref.py` (for string xrefs) and a wildcard-byte scanner
   against `/opt/brave-bin/brave`. The patterns now match because the compiler
   *and* HarfBuzz version are identical.

## Known limits

- **Sandbox.** Brave is launched with `--no-sandbox` because Frida cannot
  attach to a sandboxed renderer. The instrumented browser is materially less
  secure than normal Brave; do not sign into anything sensitive with it.
- **Text is fragmented by shape boundaries.** HarfBuzz is called per
  script-run / per font-fallback region, so a sentence like
  "Cwm fjordbank, vext quiz, 😃 glyphs" can show up as separate lines for
  `Cwm`, `fjordbank`, `vext quiz`, `😃`, `glyphs`. Reconstructing the
  original string would need correlating runs by buffer pointer and
  cluster index — out of scope for the PoC.
- **What's captured ≠ what's visible.** Off-screen and hidden DOM text still
  gets shaped, so will be captured. Conversely, text rendered into a
  `<canvas>` via direct `fillText` may bypass our hook entirely depending on
  the Skia path. WebGL text is invisible to us.
- **Cross-process dedupe.** Each renderer has its own LRU dedupe (4096
  entries). Two tabs rendering the same content will yield duplicates on
  stdout.
- **Single Brave build at a time.** Offsets are pinned to the build-id in
  `signatures.json`. Upgrading Brave breaks the hook silently — agent will
  attach but at the wrong address. Refresh the signatures (see above).
- **No chrome:// filter.** `chrome://settings`, `chrome://version`, etc. all
  render in regular renderer processes, so their text is captured too. If you
  want web-only output, filter on the consumer side.

## Files

| File | Purpose |
| --- | --- |
| [`CLAUDE.md`](./CLAUDE.md) | Project orientation for Claude (or any reader picking this up cold) — goal, constraints, source-tree map |
| [`PLAN.md`](./PLAN.md) | Implementation plan, current status, signature-refresh workflow |
| `run.py` | Launcher: profile setup, Frida spawn + child gating, message handler |
| `capture.js` | Frida agent: renderer-gated, hooks the configured offset, dedupes, sends back |
| `signatures.json` | Per-build offsets and metadata |
| `tools/find_xref.py` | `.text` scanner for RIP-relative LEA references to a target VA |
| `tools/find_hb_buffer_add.py` | Wildcard prologue scanner (work in progress) |

## Troubleshooting

**"no offsets configured" warning.** `signatures.json` still has `null`
offsets. See "Finding offsets" above.

**No output for a page that obviously has text.** Likely the offsets are
wrong (or were set for a previous Brave version). Check stderr for `hooked`
messages — if you see `hooked` lines but no `text` lines, the hook is
installed at the wrong address. Re-verify offsets.

**`Module.findBaseAddress("brave")` returns null.** The renderer process's
main module may be reported under a different name. Add the actual basename
to `MODULE_NAMES` in `capture.js`. Use Frida's REPL on the running renderer
to introspect: `frida -p <renderer_pid>` then `Process.enumerateModules()[0]`.

**Frida fails to attach to renderers.** Confirm `--no-sandbox` is in the
spawn argv — `run.py` adds it by default. Confirm child gating is enabled
(stderr should show `[child <pid>] spawned`).

**Massive output volume.** Reduce noise by tightening the dedupe window or
adding a length filter in `capture.js`. The LRU is currently size 4096 per
process.
