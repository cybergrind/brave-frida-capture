#!/usr/bin/env python3
"""brave-frida-capture launcher.

Spawns Brave with an isolated, persistent user-data-dir, attaches Frida with
child gating, injects capture.js into every renderer, and prints each unique
Unicode string Blink shapes for the screen.

Run via:
    uv run python run.py

See CLAUDE.md and PLAN.md for design and signature-refresh workflow.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import frida


HERE = Path(__file__).resolve().parent
DEFAULT_BRAVE = Path('/opt/brave-bin/brave')
DEFAULT_PROFILE = Path.home() / '.config' / 'BraveSoftware' / 'brave-frida'
DEFAULT_SIGNATURES = HERE / 'signatures.json'
DEFAULT_AGENT = HERE / 'capture.js'


def read_brave_flags_conf() -> list[str]:
    """Mirror /usr/bin/brave's behavior: pull flags from ~/.config/brave-flags.conf,
    skipping blank lines and comments. Lets the spawned Brave pick up Wayland /
    GPU flags the user has configured for their normal Brave run."""
    conf = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'brave-flags.conf'
    if not conf.exists():
        return []
    flags = []
    for raw in conf.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        flags.append(line)
    return flags


def build_argv(brave: Path, profile: Path, extra: list[str]) -> list[str]:
    return [
        str(brave),
        *read_brave_flags_conf(),
        '--no-sandbox',
        f'--user-data-dir={profile}',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-features=RendererCodeIntegrity',
        *extra,
    ]


def load_signatures(path: Path) -> dict:
    if not path.exists():
        sys.exit(f'signatures file not found: {path}')
    data = json.loads(path.read_text())
    offsets = data.get('offsets') or {}
    if not any(offsets.values()):
        sys.stderr.write(
            f'WARNING: no offsets set in {path}.\n'
            '         capture.js will load but skip hooking.\n'
            '         See PLAN.md Phase 1 for how to locate offsets.\n'
        )
    return data


def make_message_handler(pid: int):
    def handler(message, data):
        if message.get('type') == 'error':
            sys.stderr.write(f'[pid {pid}] frida error: {message.get("stack") or message.get("description")}\n')
            return
        payload = message.get('payload') or {}
        kind = payload.get('type')
        if kind == 'text':
            text = payload['text']
            sys.stdout.write(f'[pid {payload.get("pid", pid)}] {text}\n')
            sys.stdout.flush()
        elif kind in ('ready', 'skip', 'hooked', 'warn', 'error'):
            sys.stderr.write(f'[pid {pid}] {kind}: {json.dumps({k: v for k, v in payload.items() if k != "type"})}\n')
        else:
            sys.stderr.write(f'[pid {pid}] msg: {payload}\n')

    return handler


def inject(device: frida.core.Device, pid: int, agent_src: str, sig_payload: dict) -> frida.core.Session | None:
    try:
        session = device.attach(pid)
    except frida.ProcessNotFoundError:
        return None
    session.enable_child_gating()
    script = session.create_script(agent_src)
    script.on('message', make_message_handler(pid))
    script.load()
    script.post({'type': 'signatures', 'payload': sig_payload})
    return session


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--brave', type=Path, default=DEFAULT_BRAVE)
    p.add_argument(
        '--profile',
        type=Path,
        default=DEFAULT_PROFILE,
        help=f'user-data-dir; persists across runs. Default: {DEFAULT_PROFILE}',
    )
    p.add_argument('--signatures', type=Path, default=DEFAULT_SIGNATURES)
    p.add_argument('--agent', type=Path, default=DEFAULT_AGENT)
    p.add_argument('brave_args', nargs='*', help='extra args forwarded to brave (after `--`)')
    args = p.parse_args()

    if not args.brave.exists():
        sys.exit(f'brave binary not found: {args.brave}')
    args.profile.mkdir(parents=True, exist_ok=True)

    sig_data = load_signatures(args.signatures)
    sig_payload = {'offsets': sig_data.get('offsets') or {}}
    agent_src = args.agent.read_text()

    argv = build_argv(args.brave, args.profile, args.brave_args)
    sys.stderr.write(f'spawn: {" ".join(argv)}\n')
    sys.stderr.write(f'profile: {args.profile}\n')

    # Launch brave normally — letting Frida own the parent via spawn() blocks
    # Brave's startup (gpu/utility/renderer never appear). Instead we just run
    # Brave as a subprocess and use Frida only to attach to renderers as they
    # appear in /proc.
    sys.stderr.write('launching brave (subprocess, no Frida hold)\n')
    env = {**os.environ, 'CHROME_VERSION_EXTRA': 'stable'}
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.stderr.write(f'[parent {proc.pid}] brave running\n')

    device = frida.get_local_device()
    sessions: dict[int, frida.core.Session] = {}
    stop = threading.Event()

    def shutdown(*_):
        stop.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    profile_marker = f'--user-data-dir={args.profile}'

    def poll_for_renderers():
        """Scan /proc continuously for new renderer PIDs that belong to OUR
        spawned brave (matched by --user-data-dir to avoid attaching to the
        user's other Brave instance) and inject capture.js into each."""
        while not stop.is_set():
            try:
                for entry in Path('/proc').iterdir():
                    if not entry.name.isdigit():
                        continue
                    pid_n = int(entry.name)
                    if pid_n in sessions:
                        continue
                    try:
                        cmdline = (entry / 'cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8', 'replace')
                    except FileNotFoundError, PermissionError, ProcessLookupError:
                        continue
                    if profile_marker not in cmdline:
                        continue
                    if '--type=renderer' not in cmdline:
                        continue
                    # log a short cmdline tail so we can identify which tab this renderer is for
                    tail = cmdline.split('--')[-1][-160:]
                    sys.stderr.write(f'[poll-attach {pid_n}] renderer detected (...{tail})\n')
                    sess = inject(device, pid_n, agent_src, sig_payload)
                    if sess is not None:
                        sessions[pid_n] = sess
            except Exception as e:
                sys.stderr.write(f'poll error: {e}\n')
            stop.wait(1.0)

    poll_thread = threading.Thread(target=poll_for_renderers, daemon=True)
    poll_thread.start()

    sys.stderr.write('ready — Ctrl-C to stop\n')
    try:
        while not stop.is_set() and proc.poll() is None:
            time.sleep(0.5)
    finally:
        for s in sessions.values():
            with contextlib.suppress(Exception):
                s.detach()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
