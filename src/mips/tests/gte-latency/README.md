# GTE input-register latency probe

Per-input-register hardware latency tests for the PS1 GTE. For each
(instruction, input register), measures the smallest `N` such that an
`MTC2` to that register `N` nops after the GTE instruction does **not**
change the GTE's output. That `N` is the practical "instruction slots
required between the GTE op and the next write to this input" that a
developer can rely on.

## Methodology

1. Set the test scene (all GTE inputs to known baseline values).
2. Issue the GTE instruction (e.g. `cop2 NCCT(1, 1)`).
3. Insert exactly `N` nops.
4. `mtc2` a wildly different "canary" value into the target input register.
5. Drain (60 nops) so the GTE has fully completed.
6. Read RGB FIFO, MAC1/2/3, FLAG.
7. Compare to the baseline (canary lands long after completion).

The smallest `N` for which the result equals the baseline is the latch
boundary.

Per Pixel: `MTC2`/`CTC2` does not stall while a GTE op is in flight, so
the perturbing write makes it through to the GTE's register file at a
deterministic offset relative to the cop2 issue. `LWC2` is excluded
because memory-side latency would smear the boundary.

Each sweep runs twice (icache warmup, discard first). IRQs are masked
across the timed sweep so a stray interrupt cannot stretch the gap
between the cop2 op and the perturbing MTC2.

## Hardware results (SCPH-5501)

NCCT(sf=1, lm=1):

| Input register | Boundary `N` |
|----------------|-------------:|
| VXY0           |            0 |
| VXY1           |            1 |
| VXY2           |            3 |
| VZ0            |            2 |
| VZ1            |            2 |
| VZ2            |            4 |
| RGBC           |           13 |

All vertices latch in the first ~5 cycles. The vertex-color register
RGBC is read much later, around cycle 13-14, which corresponds to the
first sub-pass's color stage.

The RGBC sweep shows a clean two-step transition that points at the
hardware behavior:
- `N=0..11`: all three sub-passes see the canary RGBC.
- `N=12`: only V0 saw the original RGBC (V0's color stage has finished).
  V1 and V2 still see the canary.
- `N=13+`: all three sub-passes see the original RGBC.

This is consistent with the GTE reading RGBC once at the start of V0's
color stage (~cycle 12) and a second time covering V1+V2 (~cycle 13),
rather than re-reading per sub-pass.

## Build

```
make -C src/mips/tests/gte-latency TYPE=ps-exe
```

Produces `gte-latency.ps-exe`. Upload via Unirom + psxup.py and capture
serial output.

## Test scene

```
LLM = identity diagonal (L11=L22=L33=0x1000, off-diagonal 0)
LCM = identity diagonal
BK  = (0, 0, 0)
FC  = (0, 0, 0)
V0  = (0, 0, 0x1000)        normal facing the +Z light
V1  = (0x1000, 0, 0)        normal along +X
V2  = (0, 0x1000, 0)        normal along +Y
RGBC = (R=0x80, G=0x80, B=0x80, CODE=0)
```

Expected NCCT output for the unperturbed scene:
- `RGB0 = 0x00800000` (V0 -> blue only)
- `RGB1 = 0x00000080` (V1 -> red only)
- `RGB2 = 0x00008000` (V2 -> green only)
- `MAC = (0, 0x800, 0)` (last sub-pass, V2's color stage)

The smoke test asserts these values to catch any regression in the
expected math before the latency probes run.
