/*

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

/* Load timing tests.
 *
 * The R3000A has no data cache (that SRAM is repurposed as the scratchpad), so
 * every data load is a real access whose cost depends on what it hits. These
 * tests characterize that on real silicon:
 *
 *   loadCostByTarget - back-to-back `lw` cost per target. Scratchpad is
 *       single-cycle (on-chip SRAM, no bus); on-die MMIO is ~5 cyc; main RAM is
 *       ~7 cyc and cached (KSEG0) equals uncached (KSEG1), reconfirming there is
 *       no data cache; BIOS ROM is tens of cycles (8-bit ROM behind a slow,
 *       model-dependent ROM-bus delay - observed ~27-33 across consoles).
 *
 *   onDieUniformity - every on-die MMIO register (interrupt controller, DMA,
 *       root counters) reads at the same cost: one decoder, one latency.
 *
 *   loadShadow - the interesting one. An uncached load does NOT fully stall the
 *       pipeline: its bus access overlaps following independent instructions.
 *       But it does NOT fully hide either. Sweeping 32 loads each followed by s
 *       trailing nops, the cost-over-nops drops as s grows and then FLATLINES at
 *       ~2 cyc/load from s>=4: about half the 4-cyc bus stall overlaps trailing
 *       work, and ~2 cyc/load of bus occupancy is irreducible no matter how many
 *       independent instructions follow.
 *
 * Cycle source: root counter 2 in system-clock mode (1 tick / CPU cycle,
 * 16-bit), via the COUNTERS macro. IRQs masked suite-wide; minimum taken over
 * several runs to reject stray stalls and ensure warmed icache.
 *
 * These are hardware-timing tests: the emulator does not model these access
 * costs, so every check is a CESTER_MAYBE_TEST and is skipped under PCSX_TESTS.
 */

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/hardware/counters.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

/* Back-to-back block size and spacing-sweep load count. 256 reads = 1 KiB of
   unrolled code, inside the 4 KiB icache; 256 * ~33 cyc (slowest target) stays
   under the counter's 16-bit wrap. */
#define N_READS 256
#define N_LOADS 32

#define REP4(x)   x x x x
#define REP16(x)  REP4(x)  REP4(x)  REP4(x)  REP4(x)
#define REP32(x)  REP16(x) REP16(x)
#define REP64(x)  REP16(x) REP16(x) REP16(x) REP16(x)
#define REP128(x) REP64(x) REP64(x)
#define REP256(x) REP64(x) REP64(x) REP64(x) REP64(x)

/* Load targets, spanning the access-cost hierarchy. */
#define ADDR_SCRATCH 0x1f800000u  /* scratchpad SRAM (fast on-chip, no bus)     */
#define ADDR_ISTAT   0xbf801070u  /* on-die MMIO: interrupt controller I_STAT   */
#define ADDR_DMA     0xbf8010a0u  /* on-die MMIO: DMA channel 2 MADR            */
#define ADDR_RAM_C   0x80100000u  /* main RAM, cached mirror (KSEG0)            */
#define ADDR_RAM_U   0xa0100000u  /* main RAM, uncached mirror (KSEG1)          */
#define ADDR_BIOS    0xbfc00000u  /* BIOS ROM (KSEG1)                           */

/* One measured block = N_LOADS iterations of (lw + s nops), bracketed by two
   counter-2 reads. Defined as a macro so each spacing gets its own unrolled
   body; invoked inside CESTER_BODY below. */
#define MAKE_SPACED(name, seq)                                             \
    static __attribute__((always_inline)) uint32_t name(volatile void *p) {                              \
        register uint32_t sink;                                           \
        uint16_t before, after;                                           \
        before = COUNTERS[2].value;                                       \
        __asm__ volatile(REP32(seq) : "=&r"(sink) : "r"(p) : "memory");   \
        after = COUNTERS[2].value;                                        \
        (void)sink;                                                       \
        return (uint16_t)(after - before);                               \
    }

/* Two loads from one address separated by a gap that touches no bus at all: a
   counted loop running out of the icache. If the DRAM controller holds a row
   open and times it out, a load should cost more once the gap exceeds the
   timeout. The nop arm carries an identical delay, so the difference between
   the arms isolates the load and the nop arm's own slope calibrates
   cycles-per-delay-unit rather than my assuming it. */
#define MAKE_GAP(name, op)                                                              \
    static __attribute__((always_inline)) uint32_t name(volatile void *p, uint32_t d) { \
        register uint32_t sink;                                                         \
        uint16_t before, after;                                                         \
        before = COUNTERS[2].value;                                                     \
        __asm__ volatile(REP32(op "\n"                                                  \
                               "nop\n"                                                  \
                               "addiu %0, %0, 1\n"                                      \
                               "move $t9, %2\n"                                         \
                               "1: addiu $t9, $t9, -1\n"                                \
                               "bgtz $t9, 1b\n"                                         \
                               "nop\n")                                                 \
                         : "=&r"(sink) : "r"(p), "r"(d) : "$t9", "memory");             \
        after = COUNTERS[2].value;                                                       \
        (void)sink;                                                                      \
        return (uint16_t)(after - before);                                              \
    }

/* Store-then-load probes. The write queue is 4 words deep and is reported to act
   as a pass-through read cache; if it does, a load of an address still sitting
   in the queue is answered by the queue rather than by DRAM, and is cheaper than
   a load of an address that was never written. Both arms are interlocked so the
   load's full latency is on the critical path - without that they measure bus
   occupancy and are blind, which is how the first version of the gap probe
   wasted a ticket. */
#define MAKE_RAW(name, seq)                                                                   \
    static __attribute__((always_inline)) uint32_t name(volatile void *p, volatile void *q) { \
        register uint32_t sink;                                                               \
        uint16_t before, after;                                                               \
        before = COUNTERS[2].value;                                                           \
        __asm__ volatile(REP32(seq) : "=&r"(sink) : "r"(p), "r"(q) : "memory");                \
        after = COUNTERS[2].value;                                                             \
        (void)sink;                                                                            \
        return (uint16_t)(after - before);                                                    \
    }

/* 16 stores at fixed immediate offsets: one instruction per store, so the issue
   rate is one per cycle and the 4-deep queue actually saturates. The previous
   version bumped a pointer between stores, issuing at exactly the drain rate. */
#define SW16                                                                \
    "sw $0, 0(%0)\n"  "sw $0, 4(%0)\n"  "sw $0, 8(%0)\n"  "sw $0, 12(%0)\n" \
    "sw $0, 16(%0)\n" "sw $0, 20(%0)\n" "sw $0, 24(%0)\n" "sw $0, 28(%0)\n" \
    "sw $0, 32(%0)\n" "sw $0, 36(%0)\n" "sw $0, 40(%0)\n" "sw $0, 44(%0)\n" \
    "sw $0, 48(%0)\n" "sw $0, 52(%0)\n" "sw $0, 56(%0)\n" "sw $0, 60(%0)\n"

/* A KSEG1 store is reported not to bypass the write queue but to SYNCHRONIZE it:
   the store enters the queue, then stalls until the queue is fully drained. A
   stream of KSEG1 stores therefore shows nothing, because each one leaves the
   queue empty for the next - which is exactly what the mirror comparison
   measured. The discriminating sequence is mixed: prime the queue with N KSEG0
   stores, then issue one KSEG1 store and time it. Under that model the cost
   rises with N and knees once N reaches the queue depth, so the knee measures
   the depth from the outside. */
#define MAKE_PRIME(name, primers, tail)                                                       \
    static __attribute__((always_inline)) uint32_t name(volatile void *c, volatile void *u) { \
        uint16_t before, after;                                                               \
        before = COUNTERS[2].value;                                                           \
        __asm__ volatile(REP16(primers tail) : : "r"(c), "r"(u) : "memory");                  \
        after = COUNTERS[2].value;                                                            \
        return (uint16_t)(after - before);                                                    \
    }

#define PRIME0 ""
#define PRIME1 PRIME0 "sw $0, 0(%0)\n"
#define PRIME2 PRIME1 "sw $0, 4(%0)\n"
#define PRIME3 PRIME2 "sw $0, 8(%0)\n"
#define PRIME4 PRIME3 "sw $0, 12(%0)\n"
#define PRIME5 PRIME4 "sw $0, 16(%0)\n"
#define PRIME6 PRIME5 "sw $0, 20(%0)\n"

CESTER_BODY(
    static int s_interruptsWereEnabled;

    /* N_READS back-to-back `lw` from an address, bracketed by counter-2 reads. */
    static __attribute__((always_inline)) uint32_t timed_read(volatile void *p) {
        register uint32_t sink;
        uint16_t before, after;
        before = COUNTERS[2].value;
        __asm__ volatile(REP256("lw %0, 0(%1)\n") : "=&r"(sink) : "r"(p) : "memory");
        after = COUNTERS[2].value;
        (void)sink;
        return (uint16_t)(after - before);
    }

    /* Structurally identical baseline: same bracket, N_READS nops. */
    static __attribute__((always_inline)) uint32_t timed_nop(volatile void *p) {
        register uint32_t sink;
        uint16_t before, after;
        before = COUNTERS[2].value;
        __asm__ volatile(REP256("nop\n") : "=&r"(sink) : "r"(p) : "memory");
        after = COUNTERS[2].value;
        (void)sink;
        return (uint16_t)(after - before);
    }

    /* 128 pairs of `lw`, alternating between two addresses = 256 loads, so the
       result is directly comparable to the N_READS blocks above. With both
       pointers equal this degenerates to timed_read and must reproduce its
       figure - that equality is the instrument check for the stride sweep. */
    static __attribute__((always_inline)) uint32_t timed_pair(volatile void *a, volatile void *b) {
        register uint32_t sink;
        uint16_t before, after;
        before = COUNTERS[2].value;
        __asm__ volatile(REP128("lw %0, 0(%1)\nlw %0, 0(%2)\n")
                         : "=&r"(sink) : "r"(a), "r"(b) : "memory");
        after = COUNTERS[2].value;
        (void)sink;
        return (uint16_t)(after - before);
    }

    /* Same block shape as timed_read, but storing. Writes are buffered by the
       write queue through KSEG0; KSEG1 is documented to bypass it, so the two
       mirrors should differ for stores even though they are identical for
       loads. */
    static __attribute__((always_inline)) uint32_t timed_write(volatile void *p) {
        uint16_t before, after;
        register volatile char *q = (volatile char *)p;
        before = COUNTERS[2].value;
        __asm__ volatile(REP256("sw $0, 0(%0)\naddiu %0, %0, 4\n") : "+r"(q) : : "memory");
        after = COUNTERS[2].value;
        return (uint16_t)(after - before);
    }

    /* Same pointer walk, no store: isolates the store from the address bump. */
    static __attribute__((always_inline)) uint32_t timed_walk(volatile void *p) {
        uint16_t before, after;
        register volatile char *q = (volatile char *)p;
        before = COUNTERS[2].value;
        __asm__ volatile(REP256("nop\naddiu %0, %0, 4\n") : "+r"(q) : : "memory");
        after = COUNTERS[2].value;
        return (uint16_t)(after - before);
    }

    /* Saturating store burst: one instruction per store, 16 distinct addresses
       cycling so no two adjacent stores hit the same word. */
    static __attribute__((always_inline)) uint32_t timed_burst(volatile void *p) {
        uint16_t before, after;
        before = COUNTERS[2].value;
        __asm__ volatile(REP16(SW16) : : "r"(p) : "memory");
        after = COUNTERS[2].value;
        return (uint16_t)(after - before);
    }

    MAKE_GAP(gap_load, "lw %0, 0(%1)")
    MAKE_GAP(gap_nop, "nop")

    MAKE_PRIME(prime0, PRIME0, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime1, PRIME1, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime2, PRIME2, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime3, PRIME3, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime4, PRIME4, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime5, PRIME5, "sw $0, 0(%1)\n")
    MAKE_PRIME(prime6, PRIME6, "sw $0, 0(%1)\n")
    MAKE_PRIME(pbase0, PRIME0, "nop\n")
    MAKE_PRIME(pbase1, PRIME1, "nop\n")
    MAKE_PRIME(pbase2, PRIME2, "nop\n")
    MAKE_PRIME(pbase3, PRIME3, "nop\n")
    MAKE_PRIME(pbase4, PRIME4, "nop\n")
    MAKE_PRIME(pbase5, PRIME5, "nop\n")
    MAKE_PRIME(pbase6, PRIME6, "nop\n")

    /* Plain function, not a macro: a #define inside a cester test body is a
       preprocessor directive inside a macro argument, which does not expand. */
    typedef uint32_t (*PrimeFn)(volatile void *, volatile void *);
    static void primeRow(int n, PrimeFn sync, PrimeFn base, volatile void *c, volatile void *u) {
        uint32_t bs = 0xffffu, bb = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint32_t x = sync(c, u);
            uint32_t y = base(c, u);
            if (x < bs) bs = x;
            if (y < bb) bb = y;
        }
        ramsyscall_printf("  PRIME n=%d sync=%u base=%u delta=%d\n", n, bs, bb, (int)bs - (int)bb);
    }

    MAKE_RAW(raw_same, "sw $0, 0(%1)\nlw %0, 0(%1)\nnop\naddiu %0, %0, 1\n")
    MAKE_RAW(raw_other, "sw $0, 0(%1)\nlw %0, 0(%2)\nnop\naddiu %0, %0, 1\n")
    MAKE_RAW(raw_noload, "sw $0, 0(%1)\nnop\nnop\naddiu %0, %0, 1\n")

    MAKE_SPACED(spaced0, "lw %0, 0(%1)\n")
    MAKE_SPACED(spaced1, "lw %0, 0(%1)\nnop\n")
    MAKE_SPACED(spaced2, "lw %0, 0(%1)\nnop\nnop\n")
    MAKE_SPACED(spaced3, "lw %0, 0(%1)\nnop\nnop\nnop\n")
    MAKE_SPACED(spaced4, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(spaced5, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(spaced6, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(spaced7, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n")

    /* The load delay means the s0 version can't happen. */
    MAKE_SPACED(intlck1, "lw %0, 0(%1)\nnop\naddiu %0, 1\nnop\nnop\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(intlck2, "lw %0, 0(%1)\nnop\nnop\naddiu %0, 1\nnop\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(intlck3, "lw %0, 0(%1)\nnop\nnop\nnop\naddiu %0, 1\nnop\nnop\nnop\nnop\n")
    MAKE_SPACED(intlck4, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\naddiu %0, 1\nnop\nnop\nnop\n")
    MAKE_SPACED(intlck5, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\naddiu %0, 1\nnop\nnop\n")
    MAKE_SPACED(intlck6, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\nnop\naddiu %0, 1\nnop\n")
    MAKE_SPACED(intlck7, "lw %0, 0(%1)\nnop\nnop\nnop\nnop\nnop\nnop\nnop\naddiu %0, 1\n")

    /* Take the min over 8 runs, which should ensure warm icache and no stray stalls. */
#define BENCH(ret, fn, p) uint32_t ret; do { \
        uint32_t best = 0xffffu;             \
        for (int i = 0; i < 8; i++) {        \
            uint32_t d = fn(p);              \
            if (d < best) best = d;          \
        }                                    \
        ret = best;                          \
    } while (0);

    static void report(const char *name, uint32_t raw, uint32_t base) {
        uint32_t abs_cc = (raw * 100u + N_READS / 2) / N_READS;
        uint32_t marg_cc = ((raw - base) * 100u + N_READS / 2) / N_READS;
        ramsyscall_printf("  %s raw256=%u  abs=%u.%02u  marginal=%u.%02u cyc/read\n", name, raw,
                          abs_cc / 100u, abs_cc % 100u, marg_cc / 100u, marg_cc % 100u);
    }
)

CESTER_BEFORE_ALL(load_tests,
    /* Mask interrupts across the timed regions; set root counter 2 to the
       system-clock source (bits 8-9 = 00), free running. Writing mode resets
       the counter value to 0. */
    s_interruptsWereEnabled = enterCriticalSection();
    COUNTERS[2].mode = 0;
)

CESTER_AFTER_ALL(load_tests,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

CESTER_BEFORE_EACH(load_tests, testname, testindex,
)

CESTER_AFTER_EACH(load_tests, testname, testindex,
)

/* Back-to-back load cost per target: scratchpad ~1, MMIO ~5, RAM ~7, BIOS tens
   (model-dependent). Only the ordering and the on-die value are asserted. */
CESTER_MAYBE_TEST(loadCostByTarget, load_tests,
    BENCH(base, timed_nop,  (volatile void *)ADDR_ISTAT);
    BENCH(scratch, timed_read, (volatile void *)ADDR_SCRATCH);
    BENCH(mmio, timed_read, (volatile void *)ADDR_ISTAT);
    BENCH(ram_c, timed_read, (volatile void *)ADDR_RAM_C);
    BENCH(ram_u, timed_read, (volatile void *)ADDR_RAM_U);
    BENCH(bios, timed_read, (volatile void *)ADDR_BIOS);

    ramsyscall_printf("=== load cost by target (N=%d back-to-back) ===\n", N_READS);
    ramsyscall_printf("  nop baseline raw256=%u\n", base);
    report("scratchpad :", scratch, base);
    report("MMIO I_STAT:", mmio, base);
    report("RAM cached :", ram_c, base);
    report("RAM uncachd:", ram_u, base);
    report("BIOS ROM   :", bios, base);

    /* Scratchpad is single-cycle - as cheap as a nop, no bus involved. */
    cester_assert_true(scratch <= base + (uint32_t)N_READS / 2u);
    /* Strict cost ordering across the hierarchy. */
    cester_assert_true(scratch < mmio);
    cester_assert_true(mmio < ram_c);
    cester_assert_true(ram_c < bios);
    /* No data cache: cached and uncached main RAM cost the same (within jitter). */
    uint32_t ram_diff = ram_c > ram_u ? ram_c - ram_u : ram_u - ram_c;
    cester_assert_true(ram_diff <= (uint32_t)N_READS / 4u);
    /* On-die MMIO read ~5 cyc (4 marginal); band 3..5. */
    cester_assert_true((mmio - base) >= (uint32_t)N_READS * 3u &&
                       (mmio - base) <= (uint32_t)N_READS * 5u);
)

/* Main RAM sits behind a page-mode DRAM controller: two loads landing in the
   same row are a page hit, two in different rows force a precharge and a fresh
   activate. Sweeping the distance between two alternating load addresses should
   therefore step at the row size, which is the only way to get the array
   geometry out of software - the CPU-to-DRAM address lines are permuted (psx-spx
   records RAM.A11 wired to the chips' A8, with RAM.A8 and RAM.A10 unconnected on
   at least some retail consoles), so it cannot be read off the address map.
   Print-only: a pass threshold authored before the first hardware run is an
   assumption wearing a measurement's clothes. The single assertion below is an
   instrument check, not a claim about the phenomenon. */
CESTER_MAYBE_TEST(loadCostByStride, load_tests,
    volatile char *base = (volatile char *)ADDR_RAM_U;
    BENCH(ref, timed_read, (volatile void *)ADDR_RAM_U);

    ramsyscall_printf("=== load cost by stride (128 alternating pairs, uncached main RAM) ===\n");
    ramsyscall_printf("  Format: STRIDE <bytes> min=<ticks per 256 loads> max=<ticks> abs=<cyc/read>\n");
    ramsyscall_printf("  ref256=%u (single address, same block size)\n", ref);

    uint32_t stride0 = 0;
    for (int k = -1; k < 20; k++) {
        /* k < 0 is the stride-0 control. Strides must stay 4-byte aligned: an
           unaligned lw raises an address error, which is exactly how the first
           run of this test died one line in. */
        if (k >= 0 && k < 2) continue;
        uint32_t stride = (k < 0) ? 0u : (1u << k);
        volatile void *a = (volatile void *)base;
        volatile void *b = (volatile void *)(base + stride);
        uint32_t best = 0xffffu, worst = 0u;
        for (int i = 0; i < 8; i++) {
            uint32_t d = timed_pair(a, b);
            if (d < best) best = d;
            if (d > worst) worst = d;
        }
        if (k < 0) stride0 = best;
        uint32_t cc = (best * 100u + N_READS / 2) / N_READS;
        ramsyscall_printf("  STRIDE %u min=%u max=%u abs=%u.%02u\n", stride, best, worst, cc / 100u,
                          cc % 100u);
    }

    /* Alternating an address with itself must cost the same as 256 back-to-back
       reads of it. If this fails, the sweep is measuring something other than
       what it claims and none of the numbers above mean anything. */
    uint32_t d0 = stride0 > ref ? stride0 - ref : ref - stride0;
    cester_assert_true(d0 <= (uint32_t)N_READS / 8u);
)

/* Row-open timeout probe. The stride sweep held the inter-access gap constant at
   a few cycles, so if the controller holds rows open with a timeout, every
   sample in it was a page hit and it never generated a miss. This varies the gap
   instead, with the address fixed. A step in the load arm marks the timeout;
   a flat profile means page state is not observable in CPU-side load cost at
   all, whatever the bus is doing. Print-only, for the same reason as above. */
CESTER_MAYBE_TEST(loadCostByGap, load_tests,
    volatile void *A = (volatile void *)ADDR_RAM_U;

    ramsyscall_printf("=== load cost by inter-access gap (32 reps, one uncached RAM address) ===\n");
    ramsyscall_printf("  Format: GAP d=<delay loop count> load=<ticks> nop=<ticks> delta=<ticks per 32 loads>\n");

    for (uint32_t d = 1; d <= 48; d++) {
        uint32_t bl = 0xffffu, bn = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint32_t x = gap_load(A, d);
            uint32_t y = gap_nop(A, d);
            if (x < bl) bl = x;
            if (y < bn) bn = y;
        }
        ramsyscall_printf("  GAP d=%u load=%u nop=%u delta=%u\n", d, bl, bn,
                          bl > bn ? bl - bn : 0u);
    }
)

/* Loads cost the same through both mirrors because there is no data cache.
   Stores should not: the write queue buffers them through KSEG0 and is bypassed
   through KSEG1. */
CESTER_MAYBE_TEST(storeCostByMirror, load_tests,
    /* Sequential, not repeated: 256 stores to one address can be coalesced and
       tell you nothing about queue depth. This walks 1 KB. */
    BENCH(base, timed_walk, (volatile void *)ADDR_RAM_C);
    BENCH(w_c, timed_write, (volatile void *)ADDR_RAM_C);
    BENCH(w_u, timed_write, (volatile void *)ADDR_RAM_U);

    BENCH(nb, timed_nop, (volatile void *)ADDR_ISTAT);
    BENCH(b_c, timed_burst, (volatile void *)ADDR_RAM_C);
    BENCH(b_u, timed_burst, (volatile void *)ADDR_RAM_U);

    ramsyscall_printf("=== store cost by mirror (N=%d sequential words) ===\n", N_READS);
    ramsyscall_printf("  pointer-walk baseline raw256=%u\n", base);
    report("store KSEG0:", w_c, base);
    report("store KSEG1:", w_u, base);
    ramsyscall_printf("  --- saturating burst, 1 instr/store, nop baseline raw256=%u ---\n", nb);
    report("burst KSEG0:", b_c, nb);
    report("burst KSEG1:", b_u, nb);
)

/* Queue-depth sweep: N KSEG0 primers then one KSEG1 store. Under the
   synchronize model the KSEG1 store's cost rises with N and flattens once N
   reaches the queue depth. Print-only; the knee is the measurement. */
CESTER_MAYBE_TEST(kseg1StoreSync, load_tests,
    volatile void *C = (volatile void *)ADDR_RAM_C;
    volatile void *U = (volatile void *)ADDR_RAM_U;

    ramsyscall_printf("=== KSEG1 store sync vs primed queue depth (16 reps) ===\n");
    ramsyscall_printf("  Format: PRIME n=<KSEG0 stores ahead> sync=<ticks> base=<ticks> delta=<ticks per 16>\n");

    primeRow(0, prime0, pbase0, C, U);
    primeRow(1, prime1, pbase1, C, U);
    primeRow(2, prime2, pbase2, C, U);
    primeRow(3, prime3, pbase3, C, U);
    primeRow(4, prime4, pbase4, C, U);
    primeRow(5, prime5, pbase5, C, U);
    primeRow(6, prime6, pbase6, C, U);
)

/* Does a load of an address still in the 4-deep write queue get answered by the
   queue? If so, read-after-write is cheaper than reading a never-written
   address, and on whichever mirror bypasses the queue it is not. This decides
   whether a moving-inversions RAM test would be testing the array or the queue. */
CESTER_MAYBE_TEST(readAfterWrite, load_tests,
    volatile void *c0 = (volatile void *)ADDR_RAM_C;
    volatile void *c1 = (volatile void *)(ADDR_RAM_C + 4096u);
    volatile void *u0 = (volatile void *)ADDR_RAM_U;
    volatile void *u1 = (volatile void *)(ADDR_RAM_U + 4096u);

    uint32_t sc = 0xffffu, oc = 0xffffu, su = 0xffffu, ou = 0xffffu, nl = 0xffffu;
    for (int i = 0; i < 8; i++) {
        uint32_t a = raw_same(c0, c1);   if (a < sc) sc = a;
        uint32_t b = raw_other(c0, c1);  if (b < oc) oc = b;
        uint32_t c = raw_same(u0, u1);   if (c < su) su = c;
        uint32_t d = raw_other(u0, u1);  if (d < ou) ou = d;
        uint32_t e = raw_noload(c0, c1); if (e < nl) nl = e;
    }

    ramsyscall_printf("=== read-after-write (32 reps, interlocked) ===\n");
    ramsyscall_printf("  no-load baseline=%u\n", nl);
    ramsyscall_printf("  KSEG0 same=%u other=%u diff=%d\n", sc, oc, (int)oc - (int)sc);
    ramsyscall_printf("  KSEG1 same=%u other=%u diff=%d\n", su, ou, (int)ou - (int)su);
)

/* One on-die decoder, one latency: every on-die MMIO register reads the same. */
CESTER_MAYBE_TEST(onDieUniformity, load_tests,
    BENCH(istat, timed_read, (volatile void *)ADDR_ISTAT);
    BENCH(dma, timed_read, (volatile void *)ADDR_DMA);
    BENCH(rcnt0, timed_read, (volatile void *)&COUNTERS[0].value);
    BENCH(rcnt2, timed_read, (volatile void *)&COUNTERS[2].value);

    ramsyscall_printf("=== on-die uniformity ===\n");
    ramsyscall_printf("  I_STAT=%u DMA=%u RCNT0=%u RCNT2=%u\n", istat, dma, rcnt0, rcnt2);

    cester_assert_uint_eq(istat, dma);
    cester_assert_uint_eq(istat, rcnt0);
    cester_assert_uint_eq(istat, rcnt2);
)

/* Load shadow: an uncached load partially overlaps following independent
   instructions - neither a full stall nor fully hidden. */
CESTER_MAYBE_TEST(loadShadow, load_tests,
    volatile void *M = (volatile void *)ADDR_ISTAT;
    BENCH(s0, spaced0, M);
    BENCH(s1, spaced1, M);
    BENCH(s2, spaced2, M);
    BENCH(s3, spaced3, M);
    BENCH(s4, spaced4, M);
    BENCH(s5, spaced5, M);
    BENCH(s6, spaced6, M);
    BENCH(s7, spaced7, M);

    ramsyscall_printf("=== load-shadow sweep (%d loads + s trailing nops on MMIO) ===\n", N_LOADS);
    ramsyscall_printf("  s0=%u s1=%u s2=%u s3=%u s4=%u s5=%u s6=%u s7=%u\n", s0, s1, s2, s3, s4, s5,
                      s6, s7);

    cester_assert_uint_eq(164, s0);
    cester_assert_uint_eq(196, s1);
    cester_assert_uint_eq(228, s2);
    cester_assert_uint_eq(228, s3);
    cester_assert_uint_eq(228, s4);
    cester_assert_uint_eq(260, s5);
    cester_assert_uint_eq(292, s6);
    cester_assert_uint_eq(324, s7);
)

CESTER_MAYBE_TEST(loadInterlocked, load_tests,
    volatile void *M = (volatile void *)ADDR_ISTAT;
    BENCH(s1, intlck1, M);
    BENCH(s2, intlck2, M);
    BENCH(s3, intlck3, M);
    BENCH(s4, intlck4, M);
    BENCH(s5, intlck5, M);
    BENCH(s6, intlck6, M);
    BENCH(s7, intlck7, M);

    ramsyscall_printf("=== load-interlocked sweep (%d loads + 1 addiu after s trailing nops on MMIO) ===\n", N_LOADS);
    ramsyscall_printf("  s1=%u s2=%u s3=%u s4=%u s5=%u s6=%u s7=%u\n", s1, s2, s3, s4, s5,
                      s6, s7);

    cester_assert_uint_eq(420, s1);
    cester_assert_uint_eq(420, s2);
    cester_assert_uint_eq(388, s3);
    cester_assert_uint_eq(356, s4);
    cester_assert_uint_eq(356, s5);
    cester_assert_uint_eq(356, s6);
    cester_assert_uint_eq(356, s7);
)

CESTER_OPTIONS(
    CESTER_VERBOSE();
)
