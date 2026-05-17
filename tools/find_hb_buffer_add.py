#!/usr/bin/env python3
"""Scan .text for hb_buffer_add_utf16/utf8 prologue with wildcards.

Invariants we look for (extracted from system libharfbuzz):
  - Save all callee-saved regs:  55 48 89 e5 41 57 41 56 41 55 41 54 53
  - sub $imm8, %rsp:             48 83 ec ??
  - mov 0x20(%rdi), %eax:        8b 47 20             ; buffer->len
  - mov %eax, ??(%rbp):          89 45 ?? OR 89 44 24 ??
  - movzbl 0x4(%rdi), %eax:      0f b6 47 04          ; buffer->successful
  - test %al, %al; je rel32:     84 c0 0f 84 ?? ?? ?? ??

Reorders are common; we accept both "len-first" and "succ-first" patterns.
"""
import mmap, re, sys

BRAVE = "/opt/brave-bin/brave"
TEXT_VA   = 0x0322b000
TEXT_OFF  = 0x0322a000
TEXT_SIZE = 0x0dbcd615

PROLOGUE = bytes.fromhex("554889e54157415641554154534883ec")  # ends right before imm8

# After prologue + 1 byte (stack adj imm8), look for:
#   succ check then len read, OR len read then succ check, within next ~80 bytes
#   buffer at +0x20 (len): 8b 47 20
#   buffer at +0x4  (succ): 0f b6 47 04 84 c0 0f 84
LEN_READ  = bytes.fromhex("8b4720")
SUCC_READ = bytes.fromhex("0fb647048c0".rstrip("0"))  # placeholder
SUCC_READ_FULL = bytes.fromhex("0fb64704") + bytes.fromhex("84c0") + bytes.fromhex("0f84")

def main():
    with open(BRAVE, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    text = mm[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    print(f"Searching {len(text)/1e6:.1f} MB of .text for prologue...", file=sys.stderr)
    hits = []
    start = 0
    pcount = 0
    while True:
        idx = text.find(PROLOGUE, start)
        if idx < 0:
            break
        pcount += 1
        # window of bytes after prologue+stack_adj_byte
        window = text[idx + len(PROLOGUE) + 1 : idx + len(PROLOGUE) + 1 + 80]
        has_succ = SUCC_READ_FULL in window
        has_len  = LEN_READ in window
        if has_succ and has_len:
            va = TEXT_VA + idx
            hits.append(va)
        start = idx + 1

    print(f"prologue matches: {pcount}", file=sys.stderr)
    print(f"prologue + succ + len matches: {len(hits)}", file=sys.stderr)
    for h in hits:
        print(f"0x{h:x}")

if __name__ == "__main__":
    main()
