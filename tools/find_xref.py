#!/usr/bin/env python3
"""Find every RIP-relative LEA in .text that points at TARGET_VA."""
import mmap, struct, sys

BRAVE = "/opt/brave-bin/brave"
TEXT_VA   = 0x0322b000
TEXT_OFF  = 0x0322a000
TEXT_SIZE = 0xdbcd615
TARGET    = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x2322292

MODRMS = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}  # mod=00 rm=101

def main():
    with open(BRAVE, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    text = mm[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits = []
    i = 0
    n = len(text) - 7
    while i < n:
        b0 = text[i]
        if b0 == 0x48 or b0 == 0x4c:
            if text[i+1] == 0x8d and text[i+2] in MODRMS:
                disp = struct.unpack_from("<i", text, i+3)[0]
                va = TEXT_VA + i
                target = va + 7 + disp
                if target == TARGET:
                    hits.append(va)
        i += 1
    for h in hits:
        print(f"0x{h:x}")
    print(f"# {len(hits)} hits", file=sys.stderr)

if __name__ == "__main__":
    main()
