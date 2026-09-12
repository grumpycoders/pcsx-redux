# LZCS -> LZCR store delay: hardware results

Measured 2026-09-12 on the seele farm. Four console revisions, one run
each, 29 input values x N=0..8 x two cache regimes per run.

The console each ticket ran on was read back from its lease, not assumed
from the submitted capability request.

| Console revision | Device | Ticket | cached minN | uncached minN | shape |
|---|---|---|---|---:|---:|---|
| SCPH-1000 (NTSC-J) | seele-scph1000-2 | ticket_e823cd7c | 2 | 1 | flat |
| SCPH-1001 (NTSC-U) | seele-scph1001-0 | ticket_a522870c | 2 | 1 | flat |
| SCPH-5501 (NTSC-U) | seele-scph5501-3 | ticket_67717456 | 2 | 1 | flat |
| SCPH-7001 (NTSC-U) | seele-scph7001-5 | ticket_a40ad643 | 2 | 1 | flat |

SCPH-9002 (PAL) was submitted and never dispatched, ticket
`ticket_23c076b6` sat QUEUED. That unit advertises `flaky` and
`disc-boot`. Not measured, and nothing here should be read as covering
PAL.

`minN_range=[2..2]` cached and `[1..1]` uncached on every run, across all
29 inputs, with `n0_correct=0/29`, `never_settled=0` and `unstable=0`.

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
and it does not, anywhere, on any revision.

So: it never works with one cached opcode, and that does not depend on
the input. There is no small-input shortcut to find.

**The too-early read is a clean stale value, not garbage.** At every
sub-threshold N the readback is exactly the previous LZCS's LZCR, in
range, on every revision. There is no partial or intermediate state
visible from the CPU side.

## What this refutes

The hypothesis going in was that LZCS is an IRGB-class fan-out write: the
documented reason IRGB costs 3 rather than 2 is that it "does
additionally affect IR1,IR2,IR3", and writing LZCS additionally affects
LZCR, which is the same shape. If that held, every 2-nop LZCS site in the
tree would have been one short.

It does not hold. LZCS is a 2-cycle write. The fan-out-implies-3 reading
of that sentence is wrong, or at least does not generalise from IRGB.

## Consequence outside this directory

`src/mips/psyqo/examples/torus/torus.cpp` writes LZCS with
`GTE::Unsafe` and reads LZCR on the next line. The emitted sequence in
`torus.ps-exe`, read out of the disassembly rather than inferred from the
source, is:

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
