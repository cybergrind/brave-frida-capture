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
- A `signatures.json` with a non-null offset for `hb_shape_full` (see
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

See **[FINDING_OFFSETS.md](./FINDING_OFFSETS.md)** for the full step-by-step
procedure — that's the authoritative source, kept in sync with the actual
hook code. Short version: anchor on the `HB_SHAPER_LIST` string in
`.rodata`, walk one xref to its enclosing function
(`hb_shapers_lazy_loader_create` — not `hb_options_init`, which doesn't
exist in vendored HarfBuzz 13.x), use that function's callers to find
`hb_shape_full`, verify by disassembly heuristics, drop the offset into
`signatures.json`, run the Wikipedia verification.

`tools/find_xref.py` is a self-configuring fallback when Binja MCP is
unresponsive — reads ELF program headers to locate `.text`, no per-build
constants. Invoke as `python3 tools/find_xref.py <hex_target_va>
[path/to/binary]`.

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
| [`CLAUDE.md`](./CLAUDE.md) | Project orientation for any cold-reading agent — goal, constraints, source-tree map, current anchors |
| [`PLAN.md`](./PLAN.md) | As-built design + history of dead ends |
| [`FINDING_OFFSETS.md`](./FINDING_OFFSETS.md) | Authoritative refresh workflow for new Brave builds |
| `run.py` | Launcher: subprocess Brave, polls /proc for renderers, Frida-attach each |
| `capture.js` | Frida agent: renderer-gated, hooks `hb_shape_full`, reads `buffer->info[].codepoint`, dedupes, sends back |
| `signatures.json` | Per-build offsets, build-id, known anchors |
| `pyproject.toml` | `uv sync` then `uv run python run.py` |
| `tools/find_xref.py` | Self-configuring `.text` scanner for RIP-relative LEA refs to a target VA |
| `tools/find_hb_buffer_add.py` | Abandoned wildcard-prologue scan, kept for reference |

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
spawn argv — `run.py` adds it by default. Stderr should show
`[poll-attach <pid>] renderer detected` for each renderer; if not, the
polling loop didn't see a matching cmdline (`--user-data-dir=<profile>`
AND `--type=renderer`). On hardened kernels, also check
`cat /proc/sys/kernel/yama/ptrace_scope` — default `1` is fine
(self-spawned children) but `2` / `3` will block ptrace.

**Massive output volume.** Reduce noise by tightening the dedupe window or
adding a length filter in `capture.js`. The LRU is currently size 4096 per
process.
