# LZCS -> LZCR store delay: hardware results

Measured 2026-09-12 on the hardware farm. Four console revisions, one run
each, 126 input values x N=0..8 x two cache regimes per run.

The console each ticket ran on was read back from its lease, not assumed
from the submitted capability request.

Ticket ids are written out in full on purpose: `status`/`result` reject a
truncated prefix with `ticket_not_found`, which is the same error a
nonexistent ticket gives.

| Console revision | Device | Ticket | cached minN | uncached minN | shape |
|---|---|---|---|---:|---:|---|
| SCPH-1000 (NTSC-J) | scph1000-2 | ticket_25520514-a767-4434-9c6f-8d91096db4c6 | 2 | 1 | flat |
| SCPH-1001 (NTSC-U) | scph1001-0 | ticket_f8d8443e-7359-4d28-a3a9-f04bbff639e4 | 2 | 1 | flat |
| SCPH-5501 (NTSC-U) | scph5501-3 | ticket_0d07ac37-caf6-4657-9f0a-a2d285f2e4c5 | 2 | 1 | flat |
| SCPH-7001 (NTSC-U) | scph7001-5 | ticket_07eaf7bb-67e5-4a46-b0be-6a44ba0711dd | 2 | 1 | flat |

Two passes ran. The first swept 29 sampled values (tickets `ticket_e823cd7c-9216-4865-9675-02489363697a`,
`ticket_a522870c-ed70-4164-9b34-95781ab41116`, `ticket_67717456-a02a-44b1-861b-85a02de91de3`, `ticket_a40ad643-6894-4ae8-9d3d-2b408e3e33fc`, same four devices)
and gave the identical answer. The table above is the second pass, which
sweeps all 64 counts at two popcounts each and is the one to cite.

SCPH-9002 (PAL) was submitted twice and failed both times. Not measured,
and nothing here should be read as covering PAL.

Both attempts were leased, and both ended the same way. The submit
client's stdout does not carry the terminal state; read it back from the
lease:

| Attempt | Ticket | Lease | Terminal state | Failure |
|---|---|---|---|---|
| 1 | `ticket_23c076b6-6e71-4779-a83a-094d367801b1` | `lease_8b314334` | FAILED 19:58:56Z | `lease_timeout: Lease hard deadline expired` |
| 2 | `ticket_e6468924-40f4-4781-9e50-6d99359a21f5` | `lease_c13d532f` | FAILED 20:09:56Z | `lease_timeout: Lease hard deadline expired` |

`scph9002-6` is the ONLY device in the pool advertising `flaky`,
and its full feature set is `stock-unirom, serial-upload, disc-boot,
flaky, DFO` (read from `devices --json`, not from the label). It boots
Unirom off a disc, which is what blows the 900s lease deadline. Steer off
it with `--exclude-feature flaky`.

A third lease is not worth spending here. The result
is flat across four NTSC revisions spanning first-gen to late silicon,
and GTE latency is CPU-clock-domain - there is no mechanism by which a
PAL unit would differ. A PAL datapoint here is a nice-to-have, and this
unit costs two 15-minute leases to not get it.

`minN_range=[2..2]` cached and `[1..1]` uncached on every run, across all
126 inputs, with `n0_correct=0/126`, `never_settled=0` and `unstable=0`.

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

## Prior art, found late

This was not the first hardware measurement of the pair. A 2026-05-28
run during unrelated codec work already established the lower bound:
`>=2 cycles between mtc2 LZCS and mfc2 LZCR`, one nop not enough, `mfc2`
returning the previous write's result, from a GTE-versus-software-clz
self-test loop. That result stands and this one agrees with it.

What is new here is the shape rather than the bound: the magnitude axis
(flat, so priority encoder rather than shift-and-count), the uncached arm
(one opcode is enough), the revision sweep, and a harness that lives in
the tree instead of in a project's notes.

One difference worth stating rather than smoothing over. The earlier run
reported roughly a third of single-nop reads coming back stale. This one
reports every single-nop read stale, on 126 inputs and four consoles. The
two are consistent with a delay counted in clock cycles where surrounding
real code sometimes fills the gap on its own: this probe is a straight
line with interrupts masked and a warm icache, so nothing else can. The
earlier harness was not re-run here, so that is a reading of the
difference and not a measurement of it.

## The 256 case, specifically

`.siev` observed a case that appeared to work with one opcode and noted it
was "exactly on 256". 256 is `0x100`, which is a leading-zero run of 23,
and both run-23 entries are in the sweep:

```
LZC C v=000001ff exp=23 stale= 1 got=[1 1 23 23 23 23 23 23 23] minN=2 pos run23 dense
LZC C v=00000100 exp=23 stale= 1 got=[1 1 23 23 23 23 23 23 23] minN=2 pos run23 sparse
```

Identical on all four consoles. There is no boundary at 256 and the value
is not what made that case work. `malucart`'s guess that it was an icache
stall is the right shape: this harness runs a discarded warm-up pass and
masks interrupts specifically so that nothing can donate cycles to the
gap, and under those conditions the answer is 2 everywhere. That is a
confound controlled away, not a cold-fetch arm measured, so it supports
the icache reading without being evidence for it.
