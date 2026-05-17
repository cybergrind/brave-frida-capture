#!/usr/bin/env python3
"""Find every RIP-relative LEA in .text that points at TARGET_VA.

Reads the brave binary's program headers to locate .text dynamically — no
build-pinned constants. Works for any PIE x86-64 ELF.

Usage:
    python3 tools/find_xref.py 0x1f22292                  # default brave path
    python3 tools/find_xref.py 0x1f22292 /path/to/brave   # custom path

Prints each matching VA, one per line, plus a count to stderr.
"""

import mmap
import os
import struct
import sys


DEFAULT_BRAVE = '/opt/brave-bin/brave'

# modrm bytes for mod=00 rm=101 (RIP-relative): reg field 0..7 → 0x05,0x0d,...,0x3d
MODRMS = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}


def find_text_segment(mm: mmap.mmap) -> tuple[int, int, int]:
    """Return (text_va, text_file_off, text_size) for the first executable
    PT_LOAD in this ELF. Raises if the file isn't a 64-bit little-endian ELF
    or has no executable LOAD segment."""
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
        if p_type == 1 and (p_flags & 1):  # PT_LOAD + PF_X
            return p_vaddr, p_offset, p_filesz
    raise SystemExit('no executable PT_LOAD found')


def main() -> int:
    target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x1F22292
    path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_BRAVE
    if not os.path.exists(path):
        raise SystemExit(f'binary not found: {path}')

    with open(path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    text_va, text_off, text_size = find_text_segment(mm)
    print(
        f'# scanning {path}: .text VA=0x{text_va:x} off=0x{text_off:x} size=0x{text_size:x}',
        file=sys.stderr,
    )

    text = mm[text_off : text_off + text_size]
    hits = []
    i, n = 0, len(text) - 7
    while i < n:
        b0 = text[i]
        if b0 in (0x48, 0x4C) and text[i + 1] == 0x8D and text[i + 2] in MODRMS:
            disp = struct.unpack_from('<i', text, i + 3)[0]
            va = text_va + i
            tgt = va + 7 + disp
            if tgt == target:
                hits.append(va)
        i += 1

    for h in hits:
        print(f'0x{h:x}')
    print(f'# {len(hits)} hits', file=sys.stderr)
    return 0 if hits else 1


if __name__ == '__main__':
    raise SystemExit(main())
