# GTE input-register latency table (SCPH-5501)

For each (instruction, input register), the smallest `N` for which an
`MTC2`/`CTC2` to that register **N nops after the GTE op** does not
change the GTE's output. The smallest such `N` is the practical
"instruction slots required between the cop2 op and a write to this
input register" - safe to overwrite from then on.

Methodology and per-test detail are in [README.md](README.md). All
numbers below are hardware-verified on a single SCPH-5501 console.

## Notes on reading the table

- `N=0` means the register was already latched by the time the very
  first nop slot would have run. The MTC2 at that position arrives too
  late to affect the result.
- Triple-vertex variants (RTPT, NCT, NCCT, NCDT, DPCT) have slightly
  later boundaries because the GTE samples each vertex's data over
  the first several cycles.
- Boundaries can fluctuate by 1-2 nops between code-layout variants
  (icache alignment of the probe block matters). The tables below
  reflect the values measured in this commit.

## Perspective transforms

| Input register | RTPS (15c) | RTPT (23c) |
|----------------|-----------:|-----------:|
| VXY0 / VZ0     |       0/0  |       0/0  |
| VXY1 / VZ1     |        -   |       3/0  |
| VXY2 / VZ2     |        -   |       2/0  |
| R11R12         |          0 |          2 |
| R13R21         |          0 |          4 |
| R22R23         |          0 |          4 |
| R31R32         |          0 |          0 |
| R33            |          0 |          0 |
| TRX / TRY / TRZ|     0/0/0  |     1/4/1  |
| OFX / OFY      |       1/0  |       5/4  |
| H              |          1 |          5 |
| DQA            |          4 |          7 |
| DQB            |          3 |          6 |

## Lighting (single)

NCS, NCCS, NCDS - test scene uses non-axis-aligned V0 = (0x600, 0x800,
0xA00) so every L matrix entry contributes.

| Input register | NCS (14c) | NCCS (17c) | NCDS (19c) |
|----------------|----------:|-----------:|-----------:|
| VXY0 / VZ0     |      0/0  |       0/1  |       0/1  |
| RGBC           |       -   |          3 |          3 |
| L11L12..L31L32 |          0 |          0 |          0 |
| L33            |          0 |          0 |          0 |
| LR1LR2         |          2 |          2 |          2 |
| LR3LG1         |          1 |          1 |          1 |
| LG2LG3         |          1 |          1 |          1 |
| LB1LB2         |          2 |          2 |          2 |
| LB3            |          3 |          3 |          3 |
| RBK / GBK / BBK|     0/2/1  |       0/2/1|       0/2/1|
| RFC / GFC / BFC|       -    |       -    |     2/3/4  |

## Lighting (triple)

NCT, NCCT, NCDT.

| Input register | NCT (30c) | NCCT (39c) | NCDT (44c) |
|----------------|----------:|-----------:|-----------:|
| VXY0 / VZ0     |      0/2  |       0/2  |       0/0  |
| VXY1 / VZ1     |      0/1  |       0/1  |       0/1  |
| VXY2 / VZ2     |      1/3  |       3/3  |       3/4  |
| RGBC           |       -   |         12 |         15 |
| L11L12         |          0 |          1 |          1 |
| L13L21         |          0 |          0 |          0 |
| L22L23         |          3 |          3 |          3 |
| L31L32         |          0 |          1 |          2 |
| L33            |          0 |          1 |          2 |
| LR1LR2         |          6 |          5 |          5 |
| LR3LG1         |          3 |          3 |          4 |
| LG2LG3         |          8 |          8 |          7 |
| LB1LB2         |          8 |          7 |          7 |
| LB3            |          6 |          5 |          5 |
| RBK / GBK / BBK|     8/9/9  |     9/6/9  |     7/7/7  |
| RFC / GFC / BFC|       -    |       -    |    13/14/14|

## Color

CC and CDP use only IR / LCM / BK / RGBC (and FC for CDP).

| Input register | CC (11c) | CDP (13c) |
|----------------|---------:|----------:|
| RGBC           |        0 |         1 |
| IR0            |       -  |         2 |
| IR1 / IR2 / IR3|   1/2/2  |     2/3/2 |
| LR1LR2         |        0 |         0 |
| LR3LG1         |        0 |         0 |
| LG2LG3         |        0 |         0 |
| LB1LB2         |        1 |         1 |
| LB3            |        0 |         0 |
| RBK / GBK / BBK|   0/0/0  |     0/0/0 |
| RFC / GFC / BFC|     -    |     0/2/0 |

## Depth-cue

DPCS (8c), DPCT (17c), DCPL (8c), INTPL (8c).

| Input register | DPCS | DPCT | DCPL | INTPL |
|----------------|-----:|-----:|-----:|------:|
| RGBC           |    0 |   -  |    0 |    -  |
| RGB0           |   -  |    4 |   -  |    -  |
| RGB1           |   -  |    4 |   -  |    -  |
| RGB2           |   -  |    0 |   -  |    -  |
| IR0            |    1 |    4 |    0 |     1 |
| IR1 / IR2 / IR3|   -  |   -  | 1/0/1|  0/1/0|
| RFC / GFC / BFC|0/0/0 |1/2/3 |0/0/0 | 0/0/0 |

## Math

SQR (5c), OP (6c), NCLIP (8c).

| Input register | SQR | OP | NCLIP |
|----------------|----:|---:|------:|
| IR1 / IR2 / IR3| 0/0/1 | 0/1/0 |   -  |
| R11R12         |   - |  0 |   -  |
| R22R23         |   - |  0 |   -  |
| R33            |   - |  0 |   -  |
| SXY0           |   - |  - |    0 |
| SXY1           |   - |  - |    1 |
| SXY2           |   - |  - |    1 |

## Misc

AVSZ3 (5c), AVSZ4 (6c), GPF (5c), GPL (5c) - all simple 5-6 cycle ops.

| Input register | AVSZ3 | AVSZ4 | GPF | GPL |
|----------------|------:|------:|----:|----:|
| SZ0            |    -  |     0 |  -  |  -  |
| SZ1 / SZ2 / SZ3|  0/0/0|  0/0/0|  -  |  -  |
| ZSF3 / ZSF4    | 0 / - | - / 0 |  -  |  -  |
| IR0            |    -  |    -  |   0 |   0 |
| IR1 / IR2 / IR3|    -  |    -  |0/0/0|0/0/0|
| MAC1/2/3       |    -  |    -  |  -  |0/0/0|

## MVMVA

MVMVA is parameterized over (mx, v, cv). 8 cycles regardless of
parameter selection. Three documented variants probed:

| Input register | (RT, V0, TR) | (LL, V0, BK) | (LC, IR, BK) |
|----------------|-------------:|-------------:|-------------:|
| VXY0 / VZ0     |        0/0   |       0/2    |        -     |
| IR1 / IR2 / IR3|        -     |       -      |     1/0/1    |
| Matrix entries |        all 0 |    0/0/0/1/1 |      mostly 0|
| TR / BK        |   0/0/0      |    0/0/0     |     0/0/0    |

## Patterns

- **Inputs latch in the first ~4 cycles for nearly every instruction.**
  The GTE essentially snapshots its input register file at the start
  of execution and works from internal pipeline storage afterwards.
  Most boundaries are 0-2.

- **Triple-vertex variants extend the boundary by ~3 nops.** The GTE
  walks through V0 -> V1 -> V2 over the first several cycles before
  the matrix multiplies start in earnest.

- **DQA/DQB (RTPS depth queue) latch latest among RTPS inputs.**
  Boundaries 3-4 (RTPS) / 6-7 (RTPT). DQA/DQB are used at the end of
  the projection pipeline to compute IR0 from depth.

- **RGBC for NCC* / NCD* triples latches at cycle 12-15.** The first
  sub-pass's color stage is the read site; the FIFO push order
  suggests the GTE re-uses one snapshot of RGBC for all three vertex
  color computations.

- **FC for NCDS / NCDT / DPCT latches at cycle ~2-15.** Single-vertex
  variants read FC very early (2-4); triple variants spread reads
  across the depth-cue stages of each sub-pass.

- **Off-diagonal matrix entries with zero baseline produce N=0 even
  if they affect the result.** The methodology compares output
  values; if the canary lands and the GTE has already snapshotted the
  matrix, no change shows up. Off-diagonal entries that are 0 in the
  baseline and 0x7ff after canary perturbation but are read after the
  snapshot deadline appear identical to entries that were read
  pre-snapshot. The N=0 reading for those is correct under the
  practical "no change" definition - the developer just can't observe
  a change because the GTE has already committed.
