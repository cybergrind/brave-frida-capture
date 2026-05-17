#!/usr/bin/env python3
"""Find every direct CALL site in .text whose rel32 target equals TARGET_VA.

Scans the binary's first executable PT_LOAD for the 5-byte direct-call
encoding `E8 disp32`. Reports each call-site VA, one per line.

Use it as a Binja-free substitute for `xrefs(direction='to')` on a function
start: pass the function's VA, get every site that calls into it.

Caveats:
  - Matches direct rel32 CALLs only (opcode E8). Indirect calls through
    registers or memory (FF /2) and tail-calls via JMP rel32 (E9) are not
    matched. For HarfBuzz callsites compiled by clang this is normally
    sufficient; if a candidate function is missing from results, also try
    --include-jmp.
  - Does not validate that `E8` is the start of a real instruction (no
    full disassembly). False positives are possible inside data tables or
    in the middle of longer instructions. Cross-check each hit with
    `objdump -d --start-address=<hit-0x10> --stop-address=<hit+0x10>`.

Usage:
    python3 tools/find_callers.py 0x69df290                       # default brave
    python3 tools/find_callers.py 0x69df290 /path/to/brave        # custom path
    python3 tools/find_callers.py 0x69df290 --include-jmp         # also E9 jmps

Prints each matching VA, one per line; count to stderr.
"""

import mmap
import os
import struct
import sys


DEFAULT_BRAVE = '/opt/brave-bin/brave'


def find_text_segment(mm: mmap.mmap) -> tuple[int, int, int]:
    if mm[:4] != b'\x7fELF':
        raise SystemExit('not an ELF file')
    if mm[4] != 2 or mm[5] != 1:
        raise SystemExit('only 64-bit little-endian ELF supported')
    e_phoff = struct.unpack_from('<Q', mm, 0x20)[0]
    e_phentsz = struct.unpack_from('<H', mm, 0x36)[0]
    e_phnum = struct.unpack_from('<H', mm, 0x38)[0]
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsz
        p_type = struct.unpack_from('<I', mm, ph)[0]
        p_flags = struct.unpack_from('<I', mm, ph + 4)[0]
        p_offset = struct.unpack_from('<Q', mm, ph + 8)[0]
        p_vaddr = struct.unpack_from('<Q', mm, ph + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', mm, ph + 0x20)[0]
        if p_type == 1 and (p_flags & 1):
            return p_vaddr, p_offset, p_filesz
    raise SystemExit('no executable PT_LOAD found')


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    include_jmp = '--include-jmp' in sys.argv[1:]
    if not args:
        raise SystemExit('usage: find_callers.py <target_va> [binary] [--include-jmp]')
    target = int(args[0], 16)
    path = args[1] if len(args) > 1 else DEFAULT_BRAVE
    if not os.path.exists(path):
        raise SystemExit(f'binary not found: {path}')

    opcodes = {0xE8}
    if include_jmp:
        opcodes.add(0xE9)

    with open(path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    text_va, text_off, text_size = find_text_segment(mm)
    print(
        f'# scanning {path}: .text VA=0x{text_va:x} off=0x{text_off:x} size=0x{text_size:x}',
        file=sys.stderr,
    )

    text = mm[text_off : text_off + text_size]
    hits = []
    i, n = 0, len(text) - 5
    while i < n:
        if text[i] in opcodes:
            disp = struct.unpack_from('<i', text, i + 1)[0]
            va = text_va + i
            tgt = va + 5 + disp
            if tgt == target:
                hits.append((va, text[i]))
        i += 1

    for va, op in hits:
        kind = 'call' if op == 0xE8 else 'jmp'
        print(f'0x{va:x} {kind}')
    print(f'# {len(hits)} hits', file=sys.stderr)
    return 0 if hits else 1


if __name__ == '__main__':
    raise SystemExit(main())
