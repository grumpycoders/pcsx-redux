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
