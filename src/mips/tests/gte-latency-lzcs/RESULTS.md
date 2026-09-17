# LZCS -> LZCR store delay: hardware results

Measured 2026-09-12 on four console revisions, one run each, 126 input
rows x N=0..8 x two cache regimes per run.

| Console revision | cached minN | uncached minN | shape |
|---|---:|---:|---|
| SCPH-1000 (NTSC-J) | 2 | 1 | flat |
| SCPH-1001 (NTSC-U) | 2 | 1 | flat |
| SCPH-5501 (NTSC-U) | 2 | 1 | flat |
| SCPH-7001 (NTSC-U) | 2 | 1 | flat |

`minN_range=[2..2]` cached and `[1..1]` uncached on every run, across all
126 inputs, with `n0_correct=0/126`, `never_settled=0` and `unstable=0`.
An earlier pass over 29 sampled values on the same four consoles gave the
identical answer. No PAL unit was measured; nothing here covers PAL.

## The answer

**Cached: two filler opcodes, and two is not one short.** N=0 and N=1
both read the previous LZCS's count. N=2 reads correctly. The tree's
universal `nop; nop` is right.

**Uncached: one.** A single uncached opcode fetch is worth several cycles,
which is what psx-spx's "or one uncached opcode" is describing, and it is
enough.

**The surface is flat in input magnitude, in both regimes.** Leading-zero
runs from 1 to 32, leading-one runs from 1 to 32, and popcount varied at
fixed run length all give the same minN. That is a combinational priority
encoder. A shift-and-count would have shown minN tracking the run length,
and it does not, anywhere, on any revision. So it never works with one
cached opcode, and there is no small-input shortcut to find.

**The too-early read is a clean stale value.** At every sub-threshold N
the readback is exactly the previous LZCS's LZCR, in range, on every
revision. There is no partial or intermediate state
visible from the CPU side.

## What this refutes

The hypothesis going in was that LZCS is an IRGB-class fan-out write: the
documented reason IRGB costs 3 rather than 2 is that it "does
additionally affect IR1,IR2,IR3", and writing LZCS additionally affects
LZCR. If that held, every 2-nop LZCS site in the tree would have been
one short.

It does not hold. LZCS is a 2-cycle write. The fan-out-implies-3 reading
of that sentence is wrong, or at least does not generalise from IRGB.

## Consequence outside this directory

`src/mips/psyqo/examples/torus/torus.cpp` writes LZCS with `GTE::Unsafe`
and reads LZCR on the next line. The emitted sequence in `torus.ps-exe`,
read out of the disassembly rather than inferred from the source, is:

```
mtc2 a1,$30
nop
mfc2 v0,$31
nop            <- this one guards the GPR load delay, not the store delay
```

One filler opcode, cached. That is N=1, which this table says reads the
*previous* iteration's count. The result feeds `1 << (LZCR - 9)` as the
seed for an inverse square root, so the error is a factor of two in a
smoothly varying quantity, which is why it renders as something plausible
instead of as a crash.

Not changed here. That is a psyqo change and it is its own decision.

## Prior art

A 2026-05-28 hardware run during unrelated codec work already established
the lower bound: `>=2` cycles between `mtc2` LZCS and `mfc2` LZCR, one nop
not enough, `mfc2` returning the previous write's result. This agrees with
it. New here is the shape: the magnitude axis is flat, so a priority
encoder. Also the uncached arm, the revision sweep, and a harness that
lives in the tree.

The two runs disagree on how often a single-nop read comes back stale: the
earlier one reported roughly a third, this one reports all of them. Both
are consistent with a delay counted in clock cycles that surrounding real
code can sometimes fill on its own, which this probe cannot, since it is a
straight line with interrupts masked and a warm icache. The earlier
harness was not re-run here.

## The 256 case

256 is `0x100`, a leading-zero run of 23, and both run-23 entries are in
the sweep:

```
LZC C v=000001ff exp=23 stale= 1 got=[1 1 23 23 23 23 23 23 23] minN=2 pos run23 dense
LZC C v=00000100 exp=23 stale= 1 got=[1 1 23 23 23 23 23 23 23] minN=2 pos run23 sparse
```

Identical on all four consoles, so there is no boundary at 256 and the
input value is not what makes a one-opcode gap appear to work. An icache
stall would explain it. This harness runs a discarded warm-up pass and
masks interrupts specifically so nothing can donate cycles to the gap,
and under those conditions the answer is 2 everywhere. That controls the
stall away without measuring it, so the icache explanation is consistent
with these numbers and untested here.
