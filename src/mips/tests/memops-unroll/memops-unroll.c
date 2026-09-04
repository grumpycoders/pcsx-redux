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

/* How much is the unrolling in crt0's __wrap_memcpy / __wrap_memset actually
 * worth on real silicon, and where does it stop paying?
 *
 * Two axes, measured independently:
 *   U - words moved per loop iteration (amortizes the 2-3 instruction loop tail)
 *   B - words LOADED before any of them is STORED (copy only; sets the distance
 *       between a load and its consuming store, i.e. how much of the load
 *       shadow is covered)
 *
 * These sweeps are what set the block sizes in common/crt0/memory-s.s (memcpy
 * B=8/U=8, memset U=4) and common/psxlibc/fastmemset.s (U=4). Re-run this
 * before changing any of them.
 *
 * Cycle source and method are lifted from src/mips/tests/load-timings: root
 * counter 2 in system-clock mode (1 tick / CPU cycle, 16-bit), IRQs masked
 * suite-wide, minimum over several runs to reject stray stalls and warm the
 * icache. Every kernel is CONTENT-CHECKED before any of its timings are
 * reported - a kernel that copies the wrong number of bytes would otherwise
 * post a beautifully fast number.
 *
 * WHAT THIS RIG CAN AND CANNOT RESOLVE. The kernels are separate functions in a
 * 4 KiB direct-mapped icache with one word per line, reached through a function
 * pointer, so a kernel's ADDRESS is a variable. Two byte-identical kernels at
 * different addresses have been measured 8% apart in one binary on one console.
 * Treat any single-digit percentage from the 1 KiB tests as unresolved and
 * quote the 4096-word figures, where a per-call fill is amortised sixteen times
 * over. Two shapes of comparison here are immune and can be trusted small: the
 * same kernel called with two different POINTERS (the KSEG0/KSEG1 arms), and
 * one kernel's own cold first call against its own warm minimum.
 *
 * Hardware-timing test: the emulator models none of these costs, so every
 * check is a CESTER_MAYBE_TEST and is skipped under PCSX_TESTS.
 */

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include <stdint.h>

#include "common/hardware/counters.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

/* 256 words = 1 KiB moved per timed run. At the slowest measured rate (~9
   cyc/word for a RAM->RAM copy) that is ~2300 ticks, well inside the counter's
   16-bit wrap; and 1 KiB is exactly the size of the scratchpad, so the same
   count works for the on-chip control. */
#define WORDS 256

CESTER_BODY(
    static int s_interruptsWereEnabled;

    typedef void (*copyfn)(void *dst, const void *src, uint32_t words);
    typedef void (*setfn)(void *dst, uint32_t value, uint32_t words);

    void copy_b2_u2(void *, const void *, uint32_t);
    void copy_b4_u4(void *, const void *, uint32_t);
    void copy_b8_u8(void *, const void *, uint32_t);
    void copy_b8_u16(void *, const void *, uint32_t);
    void copy_b8_u32(void *, const void *, uint32_t);
    void copy_b2_u32(void *, const void *, uint32_t);
    void copy_b4_u32(void *, const void *, uint32_t);
    void copy_b16_u16(void *, const void *, uint32_t);
    void copy_b16_u32(void *, const void *, uint32_t);

    /* The routines actually shipped in common/crt0/memory-s.s, so the sweep
       can say whether they land on the floor it just measured rather than
       merely near it. */
    void *__wrap_memcpy(void *, const void *, uint32_t);
    void *__wrap_memset(void *, int, uint32_t);

    void set_u1(void *, uint32_t, uint32_t);
    void set_u2(void *, uint32_t, uint32_t);
    void set_u4(void *, uint32_t, uint32_t);
    void set_u8(void *, uint32_t, uint32_t);
    void set_u16(void *, uint32_t, uint32_t);
    void set_u32(void *, uint32_t, uint32_t);
    void set_u64(void *, uint32_t, uint32_t);

    /* A second, much larger pair so buffer size is an axis rather than an
       assumption. 4096 words = 16 KiB; at the slowest measured rate that is
       ~37k ticks, still inside the counter's 16-bit wrap. */
    #define BIGWORDS 4096
    static uint32_t s_bigSrc[BIGWORDS];
    static uint32_t s_bigDst[BIGWORDS];

    static uint32_t s_src[WORDS];
    static uint32_t s_dst[WORDS + 4];

    #define SCRATCH ((uint32_t *)0x1f800000u)
    #define UNCACHED(p) ((uint32_t *)(((uintptr_t)(p) & 0x1fffffffu) | 0xa0000000u))

    /* Min over 8. Also both warms the icache and rejects stray stalls, same as
       the load-timings suite. */
    /* Same as timeCopy/timeSet but parameterised on length, and reporting the
       FIRST run as well as the min. The first call to a given kernel is the
       only genuinely cold-icache one in the program, so first-vs-min is a
       direct readout of what the icache is worth here rather than a claim
       that min-over-8 handled it. */
    static uint32_t timeCopyN(copyfn fn, void *dst, const void *src, uint32_t words, uint32_t *first) {
        uint32_t best = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint16_t before = COUNTERS[2].value;
            fn(dst, src, words);
            uint16_t after = COUNTERS[2].value;
            uint32_t d = (uint16_t)(after - before);
            if (i == 0 && first) *first = d;
            if (d < best) best = d;
        }
        return best;
    }

    static uint32_t timeSetN(setfn fn, void *dst, uint32_t v, uint32_t words, uint32_t *first) {
        uint32_t best = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint16_t before = COUNTERS[2].value;
            fn(dst, v, words);
            uint16_t after = COUNTERS[2].value;
            uint32_t d = (uint16_t)(after - before);
            if (i == 0 && first) *first = d;
            if (d < best) best = d;
        }
        return best;
    }

    static uint32_t timeCopy(copyfn fn, void *dst, const void *src) {
        uint32_t best = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint16_t before = COUNTERS[2].value;
            fn(dst, src, WORDS);
            uint16_t after = COUNTERS[2].value;
            uint32_t d = (uint16_t)(after - before);
            if (d < best) best = d;
        }
        return best;
    }

    static uint32_t timeSet(setfn fn, void *dst, uint32_t v) {
        uint32_t best = 0xffffu;
        for (int i = 0; i < 8; i++) {
            uint16_t before = COUNTERS[2].value;
            fn(dst, v, WORDS);
            uint16_t after = COUNTERS[2].value;
            uint32_t d = (uint16_t)(after - before);
            if (d < best) best = d;
        }
        return best;
    }

    /* A kernel that moves the wrong amount is a fast kernel. Check before trusting. */
    static int copyCorrect(copyfn fn) {
        for (uint32_t i = 0; i < WORDS; i++) s_src[i] = i * 2654435761u + 1u;
        for (uint32_t i = 0; i < WORDS + 4; i++) s_dst[i] = 0xdeadbeefu;
        fn(s_dst, s_src, WORDS);
        for (uint32_t i = 0; i < WORDS; i++) if (s_dst[i] != s_src[i]) return 0;
        for (uint32_t i = WORDS; i < WORDS + 4; i++) if (s_dst[i] != 0xdeadbeefu) return 0;
        return 1;
    }

    static int setCorrect(setfn fn) {
        for (uint32_t i = 0; i < WORDS + 4; i++) s_dst[i] = 0xdeadbeefu;
        fn(s_dst, 0x55555555u, WORDS);
        for (uint32_t i = 0; i < WORDS; i++) if (s_dst[i] != 0x55555555u) return 0;
        for (uint32_t i = WORDS; i < WORDS + 4; i++) if (s_dst[i] != 0xdeadbeefu) return 0;
        return 1;
    }

    static void reportN(const char *name, uint32_t words, uint32_t first, uint32_t best) {
        uint32_t cc = (best * 100u + words / 2) / words;
        uint32_t fc = (first * 100u + words / 2) / words;
        ramsyscall_printf("  %-16s n=%4u  cold=%5u (%u.%02u)  min8=%5u (%u.%02u cyc/word)\n",
                          name, words, first, fc / 100u, fc % 100u, best, cc / 100u, cc % 100u);
    }

    static void reportRate(const char *name, uint32_t ticks) {
        uint32_t cc = (ticks * 100u + WORDS / 2) / WORDS;
        ramsyscall_printf("  %-14s ticks=%5u  %u.%02u cyc/word\n", name, ticks, cc / 100u, cc % 100u);
    }
)

CESTER_BEFORE_ALL(memops,
    s_interruptsWereEnabled = enterCriticalSection();
    COUNTERS[2].mode = 0;
)

CESTER_AFTER_ALL(memops,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

CESTER_BEFORE_EACH(memops, testname, testindex, )
CESTER_AFTER_EACH(memops, testname, testindex, )

/* Every kernel must move exactly 1 KiB and not one byte more. Runs first so a
   miscompiled or mis-bounded kernel fails here rather than posting a fast time. */
CESTER_TEST(kernelsCorrect, memops,
    cester_assert_true(copyCorrect(copy_b2_u2));
    cester_assert_true(copyCorrect(copy_b4_u4));
    cester_assert_true(copyCorrect(copy_b8_u8));
    cester_assert_true(copyCorrect(copy_b8_u16));
    cester_assert_true(copyCorrect(copy_b8_u32));
    cester_assert_true(copyCorrect(copy_b2_u32));
    cester_assert_true(copyCorrect(copy_b4_u32));
    cester_assert_true(copyCorrect(copy_b16_u16));
    cester_assert_true(copyCorrect(copy_b16_u32));
    cester_assert_true(setCorrect(set_u1));
    cester_assert_true(setCorrect(set_u2));
    cester_assert_true(setCorrect(set_u4));
    cester_assert_true(setCorrect(set_u8));
    cester_assert_true(setCorrect(set_u16));
    cester_assert_true(setCorrect(set_u32));
    cester_assert_true(setCorrect(set_u64));
)

/* Loop-overhead amortization for stores into main RAM. A push into the
   four-deep write queue costs one cycle (the queue depth shows up independently
   as the break in the marginal cost of the Nth store in a burst:
   1.1/2.0/2.0/2.0/2.6/4.2), so four stores per iteration is where the loop tail
   disappears under the drain and the curve goes flat. */
CESTER_MAYBE_TEST(setUnrollRam, memops,
    uint32_t t1 = timeSet(set_u1, s_dst, 0);
    uint32_t t2 = timeSet(set_u2, s_dst, 0);
    uint32_t t4 = timeSet(set_u4, s_dst, 0);
    uint32_t t8 = timeSet(set_u8, s_dst, 0);
    uint32_t t16 = timeSet(set_u16, s_dst, 0);
    uint32_t t32 = timeSet(set_u32, s_dst, 0);
    uint32_t t64 = timeSet(set_u64, s_dst, 0);
    ramsyscall_printf("=== set, main RAM cached (%d words) ===\n", WORDS);
    reportRate("U=1", t1);  reportRate("U=2", t2);  reportRate("U=4", t4);
    reportRate("U=8", t8);  reportRate("U=16", t16); reportRate("U=32", t32);
    reportRate("U=64", t64);
    cester_assert_true(t2 <= t1);
    cester_assert_true(t4 <= t2);
)

/* Same sweep with no bus underneath it: the scratchpad is on-chip SRAM, so the
   only thing unrolling can amortize is the loop tail itself. This is the
   control that says how much of the RAM curve is loop overhead and how much is
   the DRAM controller. */
CESTER_MAYBE_TEST(setUnrollScratch, memops,
    uint32_t t1 = timeSet(set_u1, SCRATCH, 0);
    uint32_t t2 = timeSet(set_u2, SCRATCH, 0);
    uint32_t t4 = timeSet(set_u4, SCRATCH, 0);
    uint32_t t8 = timeSet(set_u8, SCRATCH, 0);
    uint32_t t16 = timeSet(set_u16, SCRATCH, 0);
    uint32_t t32 = timeSet(set_u32, SCRATCH, 0);
    uint32_t t64 = timeSet(set_u64, SCRATCH, 0);
    ramsyscall_printf("=== set, scratchpad (%d words, no bus) ===\n", WORDS);
    reportRate("U=1", t1);  reportRate("U=2", t2);  reportRate("U=4", t4);
    reportRate("U=8", t8);  reportRate("U=16", t16); reportRate("U=32", t32);
    reportRate("U=64", t64);
)

/* Does the write queue serve the uncached mirror too? If KSEG1 stores bypass
   the queue, the whole unroll argument for memset only holds for KSEG0. */
CESTER_MAYBE_TEST(setUncached, memops,
    uint32_t c4 = timeSet(set_u4, s_dst, 0);
    uint32_t u4 = timeSet(set_u4, UNCACHED(s_dst), 0);
    uint32_t c64 = timeSet(set_u64, s_dst, 0);
    uint32_t u64 = timeSet(set_u64, UNCACHED(s_dst), 0);
    ramsyscall_printf("=== set, KSEG0 vs KSEG1 ===\n");
    reportRate("KSEG0 U=4", c4);   reportRate("KSEG1 U=4", u4);
    reportRate("KSEG0 U=64", c64); reportRate("KSEG1 U=64", u64);
)

/* Copy, unroll depth at fixed batch depth 8 (the shape __wrap_memcpy uses). */
CESTER_MAYBE_TEST(copyUnroll, memops,
    uint32_t u8 = timeCopy(copy_b8_u8, s_dst, s_src);
    uint32_t u16 = timeCopy(copy_b8_u16, s_dst, s_src);
    uint32_t u32 = timeCopy(copy_b8_u32, s_dst, s_src);
    ramsyscall_printf("=== copy RAM->RAM, batch 8, unroll sweep ===\n");
    reportRate("B=8 U=8", u8);   /* what the tree ships */
    reportRate("B=8 U=16", u16);
    reportRate("B=8 U=32", u32);
)

/* Copy, batch depth at fixed unroll 32 - loop overhead held constant so the
   only thing moving is how far a load sits from the store that consumes it.
   The load shadow saturates at ~4 independent instructions, so B=4 should
   already be at the floor and B=8/B=16 should buy nothing. */
CESTER_MAYBE_TEST(copyBatch, memops,
    uint32_t b2 = timeCopy(copy_b2_u32, s_dst, s_src);
    uint32_t b4 = timeCopy(copy_b4_u32, s_dst, s_src);
    uint32_t b8 = timeCopy(copy_b8_u32, s_dst, s_src);
    uint32_t b16 = timeCopy(copy_b16_u32, s_dst, s_src);
    ramsyscall_printf("=== copy RAM->RAM, unroll 32, batch sweep ===\n");
    reportRate("B=2", b2); reportRate("B=4", b4);
    reportRate("B=8", b8); reportRate("B=16", b16);
)

/* The small end: is a tight 2- or 4-word loop actually much worse than the
   shipped 8/8? This is the case that decides whether the unrolling is worth
   its icache footprint for short copies. */
CESTER_MAYBE_TEST(copySmallUnroll, memops,
    uint32_t s2 = timeCopy(copy_b2_u2, s_dst, s_src);
    uint32_t s4 = timeCopy(copy_b4_u4, s_dst, s_src);
    uint32_t s8 = timeCopy(copy_b8_u8, s_dst, s_src);
    uint32_t s16 = timeCopy(copy_b16_u16, s_dst, s_src);
    ramsyscall_printf("=== copy RAM->RAM, B==U sweep ===\n");
    reportRate("B=U=2", s2); reportRate("B=U=4", s4);
    reportRate("B=U=8", s8); reportRate("B=U=16", s16);
)

/* Closes the loop: the shipped routines against the best kernel in the sweep.
   __wrap_memset uses a 16-byte block and __wrap_memcpy a 32-byte block, both
   chosen off the numbers above, so both should sit on the floor and not merely
   near it. Everything here is 4-aligned and a whole number of blocks, which is
   the case those block loops exist for. */
CESTER_MAYBE_TEST(shippedRoutines, memops,
    uint32_t best_set = timeSet(set_u4, s_dst, 0);
    uint32_t best_copy = timeCopy(copy_b8_u8, s_dst, s_src);

    uint32_t wset = 0xffffu, wcopy = 0xffffu;
    for (int i = 0; i < 8; i++) {
        uint16_t b = COUNTERS[2].value;
        __wrap_memset(s_dst, 0, WORDS * 4);
        uint16_t a = COUNTERS[2].value;
        uint32_t d = (uint16_t)(a - b);
        if (d < wset) wset = d;
    }
    for (int i = 0; i < 8; i++) {
        uint16_t b = COUNTERS[2].value;
        __wrap_memcpy(s_dst, s_src, WORDS * 4);
        uint16_t a = COUNTERS[2].value;
        uint32_t d = (uint16_t)(a - b);
        if (d < wcopy) wcopy = d;
    }

    ramsyscall_printf("=== shipped routines vs best swept kernel ===\n");
    reportRate("kernel set U=4", best_set);
    reportRate("__wrap_memset", wset);
    reportRate("kernel copy B8U8", best_copy);
    reportRate("__wrap_memcpy", wcopy);

    /* A block loop that has fallen off its floor shows up as a double-digit
       percentage here, so 12% is loose enough not to flake on the head/tail
       handling the bare kernels do not have and tight enough to catch a
       regression to the next depth down. */
    cester_assert_true(wset <= best_set + best_set / 8u);
    cester_assert_true(wcopy <= best_copy + best_copy / 8u);
)

/* The two variables every other test here holds fixed rather than controls.

   Buffer: the rest of this file moves 1 KiB. Main RAM rows are 1 KiB (256
   columns x 4 bytes), so a 1 KiB run crosses one row boundary - the same
   crossing RATE a large linear copy sees, but a small enough sample that one
   crossing is 0.4% of the accesses. If the rates hold at 16 KiB then size is
   not a confound; if they do not, every number above is a small-buffer number.

   icache: each kernel is reached through a function pointer, and the kernels
   sit at different addresses in a 4 KiB direct-mapped cache with one word per
   line and no spatial prefetch, so body size is a per-call fill cost and code
   PLACEMENT can move a number between builds. min-over-8 warms it. Printing the
   cold first run beside the min is what turns that into a number instead of an
   assumption. */
CESTER_MAYBE_TEST(bufferSizeAndIcache, memops,
    uint32_t f;
    ramsyscall_printf("=== buffer size and cold-vs-warm ===\n");

    uint32_t b;
    b = timeSetN(set_u4, s_dst, 0, WORDS, &f);       reportN("set U=4", WORDS, f, b);
    b = timeSetN(set_u4, s_bigDst, 0, BIGWORDS, &f); reportN("set U=4", BIGWORDS, f, b);
    b = timeSetN(set_u64, s_dst, 0, WORDS, &f);      reportN("set U=64", WORDS, f, b);
    b = timeSetN(set_u64, s_bigDst, 0, BIGWORDS, &f);reportN("set U=64", BIGWORDS, f, b);

    b = timeCopyN(copy_b8_u8, s_dst, s_src, WORDS, &f);
    reportN("copy B8 U8", WORDS, f, b);
    b = timeCopyN(copy_b8_u8, s_bigDst, s_bigSrc, BIGWORDS, &f);
    reportN("copy B8 U8", BIGWORDS, f, b);
    b = timeCopyN(copy_b8_u32, s_dst, s_src, WORDS, &f);
    reportN("copy B8 U32", WORDS, f, b);
    b = timeCopyN(copy_b8_u32, s_bigDst, s_bigSrc, BIGWORDS, &f);
    reportN("copy B8 U32", BIGWORDS, f, b);
    b = timeCopyN(copy_b4_u4, s_bigDst, s_bigSrc, BIGWORDS, &f);
    reportN("copy B4 U4", BIGWORDS, f, b);
    b = timeCopyN(copy_b2_u2, s_bigDst, s_bigSrc, BIGWORDS, &f);
    reportN("copy B2 U2", BIGWORDS, f, b);
)

/* Cold cost, and where the deeper memcpy unroll stops paying for it.

   syscall_flushCache() invalidates the icache, so every "cold" figure here is
   genuinely cold rather than one-sample-per-program-run. Warm is the same
   kernel immediately after, which makes the cold/warm pair placement-immune:
   same code, same address, only the cache state differs. That pair is the
   figure the block-size rationale in memory-s.s quotes.

   The B4U4-vs-B8U8 comparison in the last two columns is NOT placement-immune -
   two different kernels at two different addresses - so read it for its shape
   and not for a crossover length. See the calibration note at the top. */
CESTER_MAYBE_TEST(coldCrossover, memops,
    static const uint32_t lens[] = { 8, 16, 32, 64, 128, 256, 512 };
    ramsyscall_printf("=== cold cost per call, B4U4 vs B8U8 (icache evicted between) ===\n");
    for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        uint32_t n = lens[i];
        uint16_t a, b;
        syscall_flushCache();
        a = COUNTERS[2].value; copy_b8_u8(s_bigDst, s_bigSrc, n); b = COUNTERS[2].value;
        uint32_t c8 = (uint16_t)(b - a);
        a = COUNTERS[2].value; copy_b8_u8(s_bigDst, s_bigSrc, n); b = COUNTERS[2].value;
        uint32_t w8 = (uint16_t)(b - a);
        syscall_flushCache();
        a = COUNTERS[2].value; copy_b4_u4(s_bigDst, s_bigSrc, n); b = COUNTERS[2].value;
        uint32_t c4 = (uint16_t)(b - a);
        a = COUNTERS[2].value; copy_b4_u4(s_bigDst, s_bigSrc, n); b = COUNTERS[2].value;
        uint32_t w4 = (uint16_t)(b - a);
        uint32_t pct8 = w8 ? ((c8 - w8) * 100u + w8 / 2u) / w8 : 0u;
        uint32_t pct4 = w4 ? ((c4 - w4) * 100u + w4 / 2u) / w4 : 0u;
        ramsyscall_printf("  n=%4u  B8U8 cold=%5u warm=%5u (+%u%%)   B4U4 cold=%5u warm=%5u (+%u%%)\n",
                          n, c8, w8, pct8, c4, w4, pct4);
    }
)

CESTER_OPTIONS(
    CESTER_VERBOSE();
)
