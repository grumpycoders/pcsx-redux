# LZCS -> LZCR store-delay probe

Measures the cop2 register *store* delay, which the sibling `gte-latency*`
binaries do not cover. Those measure how long a GTE *command* keeps
reading an input register. This one measures how long a write to a cop2
register takes to become visible, in the one place that is directly
observable with no GTE command involved: writing LZCS (cop2r30)
recomputes LZCR (cop2r31).

## Methodology

Per (input value, N):

```
mtc2 poison, $30      ; LZCR now holds lzcr(poison)
<24 nops>             ; guaranteed settled
mtc2 value,  $30
<N nops>
mfc2 out,    $31
```

The smallest N for which `out == lzcr(value)` is the answer. The poison
is picked so `lzcr(poison) != lzcr(value)` always, so a too-early read is
unambiguously stale rather than accidentally correct.

Two axes, not one:

- **N**, the filler opcode count.
- **input magnitude.** A combinational priority encoder is
  input-independent, so the smallest sufficient N is flat across inputs.
  A shift-and-count iterates, so N would track the leading-bit count and
  small inputs would settle sooner. A sweep over N alone returns one
  number and cannot tell those apart.

126 inputs cover **every** leading-zero run from 1 to 32 and **every**
leading-one run from 1 to 32, each at two popcounts: a dense value
(`0xffffffff >> k`) and a sparse one (a single bit, `1 << (31-k)`), so an
implementation whose work tracks set bits is distinguishable from one
whose work tracks the leading run.

The coverage is complete rather than sampled, and it is checked from the
run's own output rather than from this paragraph: the 126 emitted rows
must contain all 32 positive and all 32 negative counts. An earlier
version of this file swept 29 values and described them as covering
1..32, which was a sample being published as a census. That wording cost
nothing here only because someone re-derived one of its entries and
found the arithmetic wrong.

Both cache regimes are measured. psx-spx states the delay in **clock
cycles** and notes one uncached opcode substitutes for several cached
ones, so a nop-only cached sweep answers a different question in the same
units. The uncached arm calls the identical probe bodies through their
KSEG1 alias. The probe bodies are pure-register leaves (`mtc2`, `mtc2`,
`mfc2`, `jr ra`, no memory access), which is what makes that alias valid.

Controls:

- **Negative control.** N=0 must read the stale value in the cached arm,
  asserted in `lzcs_sweep_cached`. If N=0 read correctly, the sequence
  would not be exercising the hazard and every larger N would be
  uninformative rather than reassuring. There is deliberately no such
  assertion in the uncached arm, where N=0 reading correctly would be the
  documented expectation.
- **Semantics control.** `lzcs_semantics` checks the four LZCR values the
  whole probe is keyed to, using the tree's own 2-nop accessor.
- **Warm-up pass, discarded.** The first execution of each probe body is
  an icache miss in the cached regime, and a miss donates exactly the
  kind of extra cycles that would make a too-small N look sufficient.
  Warm and timed passes are compared and any disagreement is printed.
- **IRQs masked** across the timed sweep, same reason.
- `.set noreorder` around every probe body. In the assembler's default
  reorder mode GAS inserts its own nops around cop2 hazards, which would
  silently inflate N. The emitted nop counts are checked by disassembly
  after the build rather than assumed.

## Build

```
make -C src/mips/tests/gte-latency-lzcs TYPE=ps-exe
```

If the link dies on `undefined reference to vdprintf`, an openbios build
left openbios-flavoured objects in the shared `third_party/uC-sdk`
source directories. `rm third_party/uC-sdk/{libc,os}/src/*.o` and build
again.

## Reading the output

```
LZC C v=0000ffff exp=16 stale=31 got=[31 31 16 16 16 16 16 16 16] minN=2 pos run16 dense
```

`C`/`U` is the cache regime, `exp` the correct LZCR, `stale` the poison's
LZCR, `got` the readback at N=0..8, `minN` the first N that read
correctly.
