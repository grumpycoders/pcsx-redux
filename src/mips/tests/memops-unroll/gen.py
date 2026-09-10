#!/usr/bin/env python3
"""Regenerates kernels.s.

The sweep is a grid, so its assembly is data: nine copy kernels crossing batch
depth with unroll depth, seven set kernels, and an icache-sized block of nops.
Writing those by hand is 1700 lines of transcription and every one of them is a
chance to get an offset wrong - which is the bug the whole test exists to find.
Edit the COPIES and SETS lists below and re-run; do not hand-edit kernels.s.

    ./gen.py            rewrite kernels.s
    ./gen.py --check    exit non-zero if kernels.s is not what this would write
"""

import sys

LICENSE = """/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
"""

# (batch, unroll) in words. Batch = how many words are loaded before any is
# stored, which is what covers the load shadow; unroll = words per iteration,
# which is what amortises the loop tail. They are separate knobs and the point
# of the sweep is that they do not cost the same thing.
COPIES = [(2, 2), (4, 4), (8, 8), (8, 16), (8, 32), (2, 32), (4, 32), (16, 16), (16, 32)]
SETS = [1, 2, 4, 8, 16, 32, 64]

TREGS = ["$t%d" % i for i in range(8)]
SREGS = ["$s%d" % i for i in range(8)]


def copy_fn(B, U):
    """B words loaded before any is stored, U words per loop iteration.

    Both pointers are bumped at the top and the block is addressed with negative
    displacements, so the branch delay slot can carry the block's final store
    and the loop tail is 2 addiu + 1 bltu with nothing wasted. The loop ends on
    start + count-with-remainder-removed; see the note in memory-s.s about why
    it must not be written as end - blocksize.
    """
    name = "copy_b%d_u%d" % (B, U)
    regs = (TREGS + SREGS)[:B]
    need_s = B > 8
    L = ["    .global %s" % name, "    .type %s, @function" % name, "%s:" % name]
    if need_s:
        L.append("    addiu  $sp, -32")
        for i, r in enumerate(SREGS):
            L.append("    sw     %s, %d($sp)" % (r, i * 4))
    L.append("    sll    $a2, 2")
    L.append("    addu   $a3, $a0, $a2")
    L.append("1:")
    L.append("    addiu  $a1, %d" % (U * 4))
    L.append("    addiu  $a0, %d" % (U * 4))
    body = []
    base = -(U * 4)
    for blk in range(U // B):
        off = base + blk * B * 4
        for i, r in enumerate(regs):
            body.append("    lw     %s, %d($a1)" % (r, off + i * 4))
        for i, r in enumerate(regs):
            body.append("    sw     %s, %d($a0)" % (r, off + i * 4))
    L += body[:-1]
    L.append("    bltu   $a0, $a3, 1b")
    L.append(body[-1])
    if need_s:
        for i, r in enumerate(SREGS):
            L.append("    lw     %s, %d($sp)" % (r, i * 4))
        L += ["    jr     $ra", "    addiu  $sp, 32"]
    else:
        L += ["    jr     $ra", "    nop"]
    L += ["    .size %s, .-%s" % (name, name), ""]
    return "\n".join(L)


def set_fn(U):
    name = "set_u%d" % U
    L = ["    .global %s" % name, "    .type %s, @function" % name, "%s:" % name,
         "    sll    $a2, 2", "    addu   $a3, $a0, $a2", "1:",
         "    addiu  $a0, %d" % (U * 4)]
    stores = ["    sw     $a1, %d($a0)" % (-(U * 4) + i * 4) for i in range(U)]
    L += stores[:-1]
    L.append("    bltu   $a0, $a3, 1b")
    L.append(stores[-1])
    L += ["    jr     $ra", "    nop", "    .size %s, .-%s" % (name, name), ""]
    return "\n".join(L)


def build():
    out = [LICENSE + """
/* GENERATED - see gen.py. Copy and set kernels at varying unroll depth (U words
   per loop iteration) and batch depth (B words loaded before any is stored).
   Every kernel moves exactly `words` words; `words` is assumed a multiple of U. */

    .section .text, "ax", @progbits
    .set noreorder
    .align 2
"""]
    for B, U in COPIES:
        out.append(copy_fn(B, U))
    for U in SETS:
        out.append(set_fn(U))
    return "\n".join(out)


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        cur = open("kernels.s").read()
        if cur != text:
            sys.stderr.write("kernels.s does not match gen.py output\n")
            sys.exit(1)
        print("kernels.s matches gen.py output")
    else:
        open("kernels.s", "w").write(text)
        print("wrote kernels.s")
