#!/usr/bin/env python3
"""ASCII reconstruction of captured Brave page content.

Consumes the JSONL stream produced by `run.py --jsonl <file>` and prints an
ASCII grid that places text approximately where it was rendered, optionally
shading rectangles (backgrounds, dividers) behind it.

The capture pipeline emits three record kinds we care about:

  {type:"text",      pid, text}                              — content only
  {type:"draw_text", pid, kind, sx, sy, x, y, op, ...}       — position only
  {type:"draw_rect", pid, sleft, stop, sright, sbottom,
                     color, kind, op, ...}                   — geometry+color

Both `text` (from hb_shape_full) and `draw_text` (from the cc::PaintOp
dispatcher) fire inside renderer processes, and each browser tab gets
its own renderer (site-isolation). So a capture with multiple tabs
contains multiple intermixed streams — one per renderer pid. To avoid
pairing wiki text with google positions we keep a *per-pid* FIFO of
pending strings and dequeue from the matching pid's queue.

By default we render only the renderer whose last `draw_text` is most
recent — the foreground tab at end of capture. Use `--pid <pid>` to
pin a specific renderer, or `--all-pids` to overlay every renderer on
one grid (legacy behaviour, useful when only one tab is active).

Usage:
    uv run python render_ascii.py capture.jsonl
    uv run python render_ascii.py --pid 2805412 capture.jsonl
    uv run python render_ascii.py --all-pids capture.jsonl
    uv run python render_ascii.py --list-pids capture.jsonl
    uv run python render_ascii.py --cell 8x16 --out frame.txt capture.jsonl
    uv run python render_ascii.py -            # read stdin
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path


# Default cell size: a rough caricature of a 13 px UI font in a typical
# monospace terminal. Smaller cells -> bigger ASCII grid (more detail,
# wider output). Tune via --cell WxH.
DEFAULT_CELL_W = 8
DEFAULT_CELL_H = 16

# Hard caps so a stray off-screen draw doesn't blow the grid up to 100k
# columns. Real Brave viewports stay well under these.
MAX_COLS = 400
MAX_ROWS = 200

# Shade ramp by luminance (dark -> light). Five levels keeps the grid
# legible without colour. The lightest level is plain space so unpainted
# regions stay invisible.
SHADES = [' ', '░', '▒', '▓', '█']  # ' ', light, med, dark, full
# Sentinel for "rect painted, no colour info" — visible but not too noisy.
SHADE_UNKNOWN = '.'


@dataclass
class Rect:
    left: float
    top: float
    right: float
    bottom: float
    color: str  # '' or '#rrggbbaa'


@dataclass
class TextPlacement:
    sx: float
    sy: float
    content: str


@dataclass
class Frame:
    rects: list[Rect] = field(default_factory=list)
    texts: list[TextPlacement] = field(default_factory=list)
    # max observed extents, drive grid size
    max_x: float = 0.0
    max_y: float = 0.0


def parse_cell(spec: str) -> tuple[int, int]:
    try:
        w, h = spec.lower().split('x')
        return int(w), int(h)
    except Exception as e:
        raise argparse.ArgumentTypeError(f'expected WxH (e.g. 8x16), got {spec!r}') from e


def luminance_shade(color: str) -> str:
    """Map a '#rrggbbaa' colour to a shade char. Empty / unparseable → SHADE_UNKNOWN."""
    if not color or not color.startswith('#') or len(color) != 9:
        return SHADE_UNKNOWN
    try:
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        a = int(color[7:9], 16)
    except ValueError:
        return SHADE_UNKNOWN
    if a == 0:
        return ' '
    # Rec.601 luma; close enough for shade selection.
    y = 0.299 * r + 0.587 * g + 0.114 * b
    # Premultiply by alpha so fully transparent → blank.
    y *= a / 255.0
    # Map 0..255 → 0..4 with a slight bias so light backgrounds stay light.
    idx = int(y * len(SHADES) / 256.0)
    return SHADES[min(idx, len(SHADES) - 1)]


def safe_char(cp: int) -> str:
    """Render a Unicode codepoint as printable ASCII. Non-ASCII → '?'."""
    if cp == 0x20:
        return ' '
    if 0x21 <= cp <= 0x7E:
        return chr(cp)
    return '?'


def load_records(path: str):
    """Yield parsed JSON records from path (or '-' for stdin)."""
    stream = sys.stdin if path == '-' else open(path, encoding='utf-8')  # noqa: SIM115
    try:
        for raw in stream:
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as e:
                sys.stderr.write(f'skip malformed line: {e}\n')
    finally:
        if path != '-':
            stream.close()


def scan_pids(records) -> dict[int, dict]:
    """First pass over the JSONL: collect per-pid counts and the line index
    of each pid's last `draw_text`. Returns {pid: {text, draw_text,
    draw_rect, last_draw_idx}}."""
    by_pid: dict[int, dict] = defaultdict(lambda: {
        'text': 0, 'draw_text': 0, 'draw_rect': 0, 'last_draw_idx': -1,
    })
    for idx, rec in enumerate(records):
        pid = rec.get('pid')
        if pid is None:
            continue
        kind = rec.get('type')
        if kind == 'text':
            by_pid[pid]['text'] += 1
        elif kind == 'draw_text':
            by_pid[pid]['draw_text'] += 1
            by_pid[pid]['last_draw_idx'] = idx
        elif kind == 'draw_rect':
            by_pid[pid]['draw_rect'] += 1
    return dict(by_pid)


def select_pid(by_pid: dict[int, dict]) -> int | None:
    """Pick the pid whose last draw_text is most recent — i.e. the
    foreground tab at end of capture."""
    if not by_pid:
        return None
    return max(by_pid.items(), key=lambda kv: kv[1]['last_draw_idx'])[0]


def build_frame(records, accept_pid) -> tuple[Frame, dict]:
    """Walk the JSONL stream once. Returns (frame, stats).

    Correlation: a *per-pid* FIFO queue of pending text strings. Each
    `text` record enqueues into its pid's queue; each `draw_text
    DrawTextBlob` dequeues from the matching pid's queue. `draw_text`
    records without coordinates (e.g. DrawSlug) still dequeue so the
    queue doesn't drift away from the position stream.

    `accept_pid(pid) -> bool` filters which renderers contribute to the
    output. Records from rejected pids are skipped entirely.
    """
    frame = Frame()
    pending: dict[int, deque[str]] = defaultdict(deque)
    stats = {
        'text': 0,
        'draw_text': 0,
        'draw_text_placed': 0,
        'draw_text_no_text': 0,
        'draw_text_no_xy': 0,
        'draw_rect': 0,
        'unmatched_text': 0,
    }

    for rec in records:
        pid = rec.get('pid')
        if pid is None or not accept_pid(pid):
            continue
        kind = rec.get('type')
        if kind == 'text':
            txt = rec.get('text')
            if isinstance(txt, str) and txt:
                pending[pid].append(txt)
                stats['text'] += 1
        elif kind == 'draw_text':
            stats['draw_text'] += 1
            q = pending[pid]
            if rec.get('kind') != 'DrawTextBlob':
                if q:
                    q.popleft()
                continue
            sx = rec.get('sx')
            sy = rec.get('sy')
            if sx is None or sy is None:
                sx = rec.get('x')
                sy = rec.get('y')
            if sx is None or sy is None:
                stats['draw_text_no_xy'] += 1
                if q:
                    q.popleft()
                continue
            if not q:
                stats['draw_text_no_text'] += 1
                continue
            content = q.popleft()
            frame.texts.append(TextPlacement(sx=float(sx), sy=float(sy), content=content))
            stats['draw_text_placed'] += 1
            frame.max_x = max(frame.max_x, float(sx) + 8 * len(content))
            frame.max_y = max(frame.max_y, float(sy))
        elif kind == 'draw_rect':
            sl = rec.get('sleft', rec.get('left'))
            st = rec.get('stop', rec.get('top'))
            sr = rec.get('sright', rec.get('right'))
            sb = rec.get('sbottom', rec.get('bottom'))
            if sl is None or st is None or sr is None or sb is None:
                continue
            frame.rects.append(Rect(left=float(sl), top=float(st), right=float(sr), bottom=float(sb),
                                    color=rec.get('color') or ''))
            stats['draw_rect'] += 1
            frame.max_x = max(frame.max_x, float(sr))
            frame.max_y = max(frame.max_y, float(sb))
    stats['unmatched_text'] = sum(len(q) for q in pending.values())
    return frame, stats


def render(frame: Frame, cell_w: int, cell_h: int) -> str:
    cols = min(MAX_COLS, max(1, int(frame.max_x // cell_w) + 2))
    rows = min(MAX_ROWS, max(1, int(frame.max_y // cell_h) + 2))

    grid = [[' '] * cols for _ in range(rows)]

    # Pass 1 — rect backgrounds, in observation order. Later rects overpaint
    # earlier ones (matches the actual paint order). Use SHADE_UNKNOWN for
    # geometry-only rects (the SkCanvas::drawRect hook).
    for r in frame.rects:
        c0 = max(0, int(r.left  // cell_w))
        c1 = min(cols, int(r.right  // cell_w) + 1)
        r0 = max(0, int(r.top   // cell_h))
        r1 = min(rows, int(r.bottom // cell_h) + 1)
        if c1 <= c0 or r1 <= r0:
            continue
        ch = luminance_shade(r.color)
        # Fully-transparent rects are no-ops (keep underlying shade).
        if ch == ' ':
            continue
        for y in range(r0, r1):
            row = grid[y]
            for x in range(c0, c1):
                row[x] = ch

    # Pass 2 — text overlay. Plain ASCII overwrites whatever shade was there.
    for tp in frame.texts:
        c = int(tp.sx // cell_w)
        r = int(tp.sy // cell_h)
        if r < 0 or r >= rows:
            continue
        row = grid[r]
        for offset, cp in enumerate(tp.content):
            x = c + offset
            if x < 0:
                continue
            if x >= cols:
                break
            row[x] = safe_char(ord(cp))

    return '\n'.join(''.join(line).rstrip() for line in grid)


# ANSI control: move cursor to home, clear-to-end-of-screen. Avoids the
# scroll-back trash of `clear` and keeps the terminal scrollback clean.
ANSI_HOME_CLEAR = '\033[H\033[J'


def render_once(path: str, args) -> tuple[str, dict, int | None, str, dict]:
    """Read the whole file, pick the rendered pid, build the frame, render
    to ASCII. Returns (output, stats, chosen_pid, chosen_msg, by_pid)."""
    all_records = list(load_records(path))
    by_pid = scan_pids(all_records)
    if args.all_pids:
        chosen, chosen_msg = None, 'all pids'
    elif args.pid is not None:
        chosen = args.pid
        chosen_msg = f'pid {chosen}' if chosen in by_pid else f'pid {chosen} (not yet present)'
    else:
        chosen = select_pid(by_pid)
        chosen_msg = f'pid {chosen} (auto-selected: latest draw_text)'
    accept = (lambda _pid: True) if chosen is None else (lambda p_: p_ == chosen)
    frame, stats = build_frame(all_records, accept)
    cell_w, cell_h = args.cell
    return render(frame, cell_w, cell_h), stats, chosen, chosen_msg, by_pid


def watch_loop(path: str, args) -> int:
    """Tail-follow the JSONL: re-render whenever (size, mtime) changes.
    Robust to the `'w'`-mode truncation that `run.py` does at session
    start. Ctrl-C exits cleanly."""
    interval = max(0.05, args.watch_interval)
    file_path = Path(path)
    last_sig: tuple[int, float] | None = None
    sys.stdout.write(ANSI_HOME_CLEAR + f'waiting for {file_path} ...\n')
    sys.stdout.flush()
    try:
        while True:
            try:
                st = file_path.stat()
            except FileNotFoundError:
                time.sleep(interval)
                continue
            sig = (st.st_size, st.st_mtime)
            if sig != last_sig:
                last_sig = sig
                try:
                    output, stats, _chosen, chosen_msg, by_pid = render_once(path, args)
                except Exception as e:  # noqa: BLE001  (don't crash the watch loop)
                    sys.stdout.write(ANSI_HOME_CLEAR + f'render error: {e!r}\n')
                    sys.stdout.flush()
                    time.sleep(interval)
                    continue
                footer = (
                    f'-- watching {file_path} -- {chosen_msg} -- '
                    f'placed={stats["draw_text_placed"]} '
                    f'no_text={stats["draw_text_no_text"]} '
                    f'rects={stats["draw_rect"]} pids={len(by_pid)} '
                    f'bytes={st.st_size}\n'
                )
                sys.stdout.write(ANSI_HOME_CLEAR + output + '\n' + footer)
                sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write('\n')
        return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('jsonl', help='JSONL capture file, or "-" for stdin')
    p.add_argument(
        '--cell',
        type=parse_cell,
        default=(DEFAULT_CELL_W, DEFAULT_CELL_H),
        help=f'cell size WxH in pixels (default {DEFAULT_CELL_W}x{DEFAULT_CELL_H})',
    )
    p.add_argument('--out', type=Path, default=None, help='write ASCII to file instead of stdout')
    p.add_argument(
        '--stats',
        action='store_true',
        help='print correlation stats to stderr after rendering',
    )
    p.add_argument(
        '--pid', type=int, default=None,
        help='render only this renderer pid (default: pid with latest draw_text — the foreground tab)',
    )
    p.add_argument(
        '--all-pids', action='store_true',
        help='render every renderer onto one grid (legacy behaviour)',
    )
    p.add_argument(
        '--list-pids', action='store_true',
        help='print per-pid record counts to stderr and exit without rendering',
    )
    p.add_argument(
        '--watch', action='store_true',
        help='tail-follow the JSONL and re-render on every change (Ctrl-C to exit)',
    )
    p.add_argument(
        '--watch-interval', type=float, default=0.25,
        help='seconds between watch polls (default 0.25)',
    )
    args = p.parse_args()

    if args.pid is not None and args.all_pids:
        p.error('--pid and --all-pids are mutually exclusive')
    if args.watch:
        if args.jsonl == '-':
            p.error('--watch needs a file path, not stdin')
        if args.out is not None:
            p.error('--watch and --out are mutually exclusive')
        if args.list_pids:
            p.error('--watch and --list-pids are mutually exclusive')
        return watch_loop(args.jsonl, args)

    # We need two passes: one to discover pids, one to render. Materialise.
    all_records = list(load_records(args.jsonl))
    by_pid = scan_pids(all_records)

    if args.list_pids or args.stats:
        for pid, counts in sorted(by_pid.items(), key=lambda kv: -kv[1]['last_draw_idx']):
            sys.stderr.write(
                f'pid {pid}: text={counts["text"]} draw_text={counts["draw_text"]} '
                f'draw_rect={counts["draw_rect"]} last_draw_idx={counts["last_draw_idx"]}\n'
            )
        if args.list_pids:
            return 0

    if args.all_pids:
        chosen = None  # accept all
        chosen_msg = 'all pids'
    elif args.pid is not None:
        if args.pid not in by_pid:
            sys.stderr.write(
                f'pid {args.pid} not present in capture; available pids: '
                f'{sorted(by_pid)}\n'
            )
            return 2
        chosen = args.pid
        chosen_msg = f'pid {chosen}'
    else:
        chosen = select_pid(by_pid)
        chosen_msg = f'pid {chosen} (auto-selected: latest draw_text)'

    accept = (lambda _pid: True) if chosen is None else (lambda p_: p_ == chosen)

    frame, stats = build_frame(all_records, accept)
    cell_w, cell_h = args.cell
    output = render(frame, cell_w, cell_h)

    if args.out is not None:
        args.out.write_text(output + '\n', encoding='utf-8')
    else:
        sys.stdout.write(output + '\n')

    if args.stats:
        sys.stderr.write(
            f'rendering {chosen_msg}: text={stats["text"]} draw_text={stats["draw_text"]} '
            f'placed={stats["draw_text_placed"]} no_text={stats["draw_text_no_text"]} '
            f'no_xy={stats["draw_text_no_xy"]} draw_rect={stats["draw_rect"]} '
            f'unmatched_text={stats["unmatched_text"]} '
            f'grid={min(MAX_COLS, max(1, int(frame.max_x // cell_w) + 2))}'
            f'x{min(MAX_ROWS, max(1, int(frame.max_y // cell_h) + 2))} '
            f'cell={cell_w}x{cell_h}\n'
        )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
