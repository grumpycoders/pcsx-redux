# MMIO partial-word write masking - SCPH-5501

Hardware results from running `regwrites.ps-exe` on a single retail
SCPH-5501. Raw serial log at [scph5501-raw.log](scph5501-raw.log).

## Test setup

For each (target register, op, byte offset, baseline pattern, source
pattern) the driver writes the baseline via the natural-width store,
runs the test op via an asm trampoline (`asm.s`, so the compiler
cannot legalize it), then reads back. Three baselines (`0x00000000`,
`0xFFFFFFFF`, `0x11223344`) and two sources (`0xAABBCCDD`,
`0xFEDCBA98`) per (target, op, offset) triple.

The cop0 exception handler from `../cop0/exceptions.cpp` is wired in
so misaligned `sh` traps (AdES) are recorded and skipped without
killing the test.

## On-die MMIO: byte enables ignored, full bus latched

DPCR (`0x1F8010F0`, 32-bit, R/W, the cleanest readback target).
Source `0xAABBCCDD`, identical results across all baselines:

| op    | offset | got           | bus model                |
|-------|--------|---------------|--------------------------|
| `sw`  | +0     | `0xAABBCCDD`  | control                  |
| `sb`  | +0     | `0xAABBCCDD`  | `src << 0`               |
| `sb`  | +1     | `0xBBCCDD00`  | `src << 8`               |
| `sb`  | +2     | `0xCCDD0000`  | `src << 16`              |
| `sb`  | +3     | `0xDD000000`  | `src << 24`              |
| `sh`  | +0     | `0xAABBCCDD`  | `src << 0`               |
| `sh`  | +2     | `0xCCDD0000`  | `src << 16`              |
| `sh`  | +1     | AdES          | misaligned, traps        |
| `sh`  | +3     | AdES          | misaligned, traps        |
| `swl` | +0     | `0x000000AA`  | `src >> 24`              |
| `swl` | +1     | `0x0000AABB`  | `src >> 16`              |
| `swl` | +2     | `0x00AABBCC`  | `src >> 8`               |
| `swl` | +3     | `0xAABBCCDD`  | `src >> 0`               |
| `swr` | +0     | `0xAABBCCDD`  | `src << 0` (= `sw`)      |
| `swr` | +1     | `0xBBCCDD00`  | `src << 8`               |
| `swr` | +2     | `0xCCDD0000`  | `src << 16`              |
| `swr` | +3     | `0xDD000000`  | `src << 24`              |

The on-die MMIO bus is 32 bits wide. The CPU drives `bus = shift(src, off)`
and the decoder latches the entire word, regardless of which byte enables
are asserted. Identical results across all three baselines - the baseline
contributes nothing, the entire register is overwritten with the shifted
source word. With baseline `0xFFFFFFFF`, an `swr +1` produces `0xBBCCDD00`:
byte 0 is `0x00` (from the bus), not `0xFF` (preserved baseline). Byte
enables are not honored.

The misaligned `sh` cases trap with `cause=0x10000014` (ExcCode 5, AdES),
`EPC` pointing at the trampoline's `sh` instruction, and `badvaddr`
reporting the unaligned effective address. The exception fires before the
bus transaction, so the register is unchanged.

IMASK (`0x1F801074`, 32-bit, low 11 bits valid) shows the same shift
pattern in its valid bits. Upper 21 bits read back as `0xBF800xxx` -
open-bus / address-decoder echo of the IMASK address.

## SBUS: per-device data width, BIU dispatches per-halfword

The SPU sits behind the SBUS, an off-die system bus (`SBUS.D0..D15`,
`SBUS.A0..A23`) shared with BIOS, CD-ROM, and Expansion ports. The bus's
data path width is configured PER-DEVICE via bit 12 of each device's
Delay/Size register (`0x1F801008..0x1F80101C`): CD-ROM and BIOS ROM are
8-bit (using `SBUS.D[7:0]` only); SPU is 16-bit (using `SBUS.D[15:0]`);
expansion can use either. The bus has two write-strobe lines: `SBUS./WR0`
(lower byte of halfword) and `SBUS./WR1` (upper byte). For a 32-bit CPU
access, the bus interface unit (BIU) decomposes the access into 2
consecutive transactions on a 16-bit device, or 4 on an 8-bit device,
keeping `/CS` active and stepping the address.

The rules below were measured against the SPU (16-bit configured). The
8-bit case (CD-ROM, BIOS ROM) issues a different number of transactions
per access and was not measured here. The complete model that fits every
SPU observation:

**BIU dispatch (CPU access -> SBUS transactions):**

1. A 4-byte CPU access (`sw`, `swl +3`, `swr +0`) issues TWO SBUS
   transactions, one per halfword.
2. A 1-, 2-, or 3-byte CPU access issues ONE transaction, at the
   halfword containing the lowest enabled byte. Bytes outside that
   halfword are silently dropped.
3. Strobe assertion per issued halfword:
   - 1-byte access (`sb`, `swl +0`, `swr +3`): asserts only `/WR0`
     (low byte of halfword) or `/WR1` (high byte of halfword) per
     the addressed lane.
   - 2-or-more-byte access: asserts BOTH `/WR0` and `/WR1` on each
     issued halfword, regardless of which CPU-side lanes were
     enabled within it.

**SPU rule:** latches the full SBUS data halfword whenever `/WR0`
strobes. `/WR1` strobing alone is ignored.

The SPU's 16-bit-write-only behavior is documented in the pinout notes:
"all system bus devices are either 8-bit (CD-ROM, BIOS ROM) or only
support 16-bit writes (SPU)" and "`SBUS./WR1` is routed to the
expansion port but otherwise left unused." The model is compatible with
the SPU silicon ignoring the `/WR0` vs `/WR1` distinction internally and
only ever doing halfword latches; what we read here as "`/WR0` matters,
`/WR1` doesn't" is the BIU+SPU pair behaving as if `/WR1` is unwired
on the SPU's `/CS4` path.

### `sb` to MAINVOL_L (`0x1F801D80`), source `0xAABBCCDD`

The four-offset matrix (the high-byte rows are the same in pattern;
only the low-byte rows differ in which halfword they hit):

| op | byte | issued halfword | strobe | bus halfword | reg got | neighbor got |
|---|---|---|---|---|---|---|
| `sb +0` | 0 | low (MAINVOL_L) | `/WR0` only | `0xCCDD` | `0xCCDD` | baseline |
| `sb +1` | 1 | low (MAINVOL_L) | `/WR1` only | `0xDD00` | baseline | baseline |
| `sb +2` | 2 | high (MAINVOL_R) | `/WR0` only | `0xCCDD` | baseline | `0xCCDD` |
| `sb +3` | 3 | high (MAINVOL_R) | `/WR1` only | `0xCC00` | baseline | baseline |

Symmetry holds: lane 0 / lane 2 (`/WR0` cases) latch a full halfword
into the addressed register or its neighbor; lane 1 / lane 3 (`/WR1`
cases) drop entirely. Verified across baselines `0x0000`, `0xFFFF`,
`0x3344` - in every drop case both halves track baseline.

### `swl` / `swr` to MAINVOL_L, source `0xAABBCCDD`, baseline `0`

| op | bytes written | issued halfword | bus halfword | reg got | neighbor got |
|---|---|---|---|---|---|
| `swl +0` | 1 (byte 0) | low (`/WR0` only) | `0x00AA` | `0x00AA` | `0x0000` |
| `swl +1` | 2 (bytes 0..1) | low (both strobes) | `0xAABB` | `0xAABB` | `0x0000` |
| `swl +2` | 3 (bytes 0..2) | low (both strobes) | `0xBBCC` | `0xBBCC` | `0x0000` |
| `swl +3` | 4 (bytes 0..3) | both | `0xCCDD` / `0xAABB` | `0xCCDD` | `0xAABB` |
| `swr +0` | 4 (bytes 0..3) | both | `0xCCDD` / `0xAABB` | `0xCCDD` | `0xAABB` |
| `swr +1` | 3 (bytes 1..3) | low (both strobes) | `0xDD00` | `0xDD00` | `0x0000` |
| `swr +2` | 2 (bytes 2..3) | high (both strobes) | `0xCCDD` | `0x0000` | `0xCCDD` |
| `swr +3` | 1 (byte 3) | high (`/WR1` only) | `0xDD00` | `0x0000` | `0x0000` |

The two key informative rows:

- **`swl +2` (3-byte spanning write):** writes bytes 0+1+2. Lowest
  enabled byte is 0 (low halfword). One transaction at the low
  halfword with both strobes asserted (>=2-byte access rule). High
  halfword: silently dropped, despite byte 2 being inside it.
- **`swr +1` (3-byte spanning write):** writes bytes 1+2+3. Lowest
  enabled byte is 1 (low halfword). One transaction at the low
  halfword with both strobes asserted. High halfword bytes 2+3:
  silently dropped.

Voice 0 left volume (`0x1F801C00`) gives identical results to
MAINVOL_L. The behavior is a property of the SBUS path, not of any
individual SPU register.

## Practical implications

- Setting one byte of a 32-bit MMIO register via `sb` does not work
  on PS1. The whole register is overwritten with `src << offset*8`.
- An `sw` to a 16-bit SPU register also writes the neighbor (the
  4-byte access gets split into two 16-bit SBUS transactions). Use
  `sh` for single-register writes.
- An `sb` to the high byte of any halfword in an SBUS region (lane
  1 or lane 3 within the word, or any lane that lands on `/WR1`)
  is a silent no-op on the SPU. Other SBUS devices may behave
  differently; this is verified for SPU.
- Read-modify-write idioms like `*reg |= mask` are safe only when
  the compiler emits a 32-bit `lw` + `sw` (for on-die MMIO) or a
  16-bit `lh` + `sh` (for SPU). Any sub-word degradation silently
  smashes the register or no-ops.
- Misaligned `sh` (`+1`/`+3`) AdES-traps cleanly; the register is
  not modified before the trap.
- Emulators that implement byte-enable masking on the MMIO write
  path (or that don't model the SBUS dispatch policy) will be more
  permissive than silicon. Hardware-only failures with this
  signature fit this discrepancy.

## Open follow-ups

- GPU GP0 / GP1 (VBUS): 32-bit bus, no width masking, exactly one
  decoded address bit. All four `sb` offsets within either port
  collapse to the same write target. Both ports are write-only with
  side effects, so a clean readback path needs more care.
- Timer mode registers: R/W, but writing has the side effect of
  resetting the counter. Not safe in the current shared-driver
  loop.
- CD-ROM and BIOS ROM: also on SBUS but the I/O semantics are
  different (CDROM register file, BIOS read-only). Worth probing
  to see whether the BIU rules apply uniformly across SBUS devices.
