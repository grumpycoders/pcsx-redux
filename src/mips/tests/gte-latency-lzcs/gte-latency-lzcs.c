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

// LZCS -> LZCR store-delay probe.
//
// The sibling gte-latency* binaries measure how long a GTE *command*
// keeps reading an input register. This one measures the cop2 register
// *store* delay in the only place it is directly observable: writing
// LZCS (cop2r30) recomputes LZCR (cop2r31), so the fan-out is visible
// through a single mfc2 with no GTE command involved.
//
// Sequence, per (value, N):
//
//     mtc2 poison, $30      ; LZCR now holds lzcr(poison)
//     <DRAIN nops>          ; guaranteed settled
//     mtc2 value,  $30
//     <N nops>
//     mfc2 out,    $31
//
// The smallest N for which out == lzcr(value) is the answer. N = 0 must
// read lzcr(poison) or the sequence is not exercising the hazard at all
// and every larger N is uninformative rather than reassuring.
//
// Two axes on purpose:
//   N              - filler opcode count.
//   input magnitude - a combinational priority encoder is
//                    input-independent, so the smallest sufficient N is
//                    flat across values; a shift-and-count iterates, so
//                    N would track the leading-bit count. A sweep over N
//                    alone returns one number and cannot tell those
//                    apart. The shape of the surface is the finding.
//
// Both regimes are measured. psx-spx states the delay in CLOCK CYCLES
// and notes one uncached opcode substitutes for several cached ones, so
// a nop-only cached sweep answers a different question in the same
// units. The uncached arm runs the identical code through its KSEG1
// alias.

#include "common/hardware/cop2.h"
#include "common/syscalls/syscalls.h"

// clang-format off

#ifndef GTE_LATENCY_LZCS_HELPERS_DEFINED
#define GTE_LATENCY_LZCS_HELPERS_DEFINED

#define MAX_N 8
#define DRAIN 24

#define LZC_STR_(x) #x
#define LZC_STR(x) LZC_STR_(x)

// Enable COP2 by setting CU2 in CP0 SR.
static inline void lzc_gte_enable(void) {
    uint32_t sr;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr));
    sr |= 0x40000000;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

// Mask interrupts across the timed sequence. A stray IRQ landing between
// the mtc2 and the mfc2 donates cycles to the hazard and makes a
// too-small N read correct, which is the direction that produces a wrong
// and reassuring answer.
static inline uint32_t lzc_irq_disable(void) {
    uint32_t sr_orig, sr_new;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr_orig));
    sr_new = sr_orig & ~1u;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr_new));
    return sr_orig;
}

static inline void lzc_irq_restore(uint32_t sr) {
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

// ==========================================================================
// Probe bodies. One global function per N so the same code can be called
// through its KSEG1 (uncached) alias without recompiling.
//
// .set noreorder is load-bearing: with the assembler's default reorder
// mode GAS is free to insert its own nops around the cop2 hazards, which
// would silently inflate N and make the whole measurement a fiction.
// The disassembly is checked after the build, not assumed.
// ==========================================================================

#define MK_LZC_FN(N)                                                       \
    uint32_t __attribute__((noinline))                                     \
    lzc_probe_##N(uint32_t poison, uint32_t value) {                       \
        uint32_t out;                                                      \
        __asm__ volatile(                                                  \
            ".set push\n\t"                                                \
            ".set noreorder\n\t"                                           \
            "mtc2 %1, $30\n\t"                                             \
            ".rept " LZC_STR(DRAIN) "\n\tnop\n\t.endr\n\t"                 \
            "mtc2 %2, $30\n\t"                                             \
            ".rept " #N "\n\tnop\n\t.endr\n\t"                             \
            "mfc2 %0, $31\n\t"                                             \
            "nop\n\t"                                                      \
            "nop\n\t"                                                      \
            ".set pop\n\t"                                                 \
            : "=&r"(out)                                                   \
            : "r"(poison), "r"(value));                                    \
        return out;                                                        \
    }

MK_LZC_FN(0)
MK_LZC_FN(1)
MK_LZC_FN(2)
MK_LZC_FN(3)
MK_LZC_FN(4)
MK_LZC_FN(5)
MK_LZC_FN(6)
MK_LZC_FN(7)
MK_LZC_FN(8)

typedef uint32_t (*lzc_probe_fn)(uint32_t, uint32_t);

static lzc_probe_fn const g_probes[MAX_N + 1] = {
    lzc_probe_0, lzc_probe_1, lzc_probe_2, lzc_probe_3, lzc_probe_4,
    lzc_probe_5, lzc_probe_6, lzc_probe_7, lzc_probe_8,
};

#define KSEG1(p) ((lzc_probe_fn)(((uint32_t)(p)) | 0xa0000000u))

// ==========================================================================
// Test vectors. Magnitude axis, both signs, with popcount deliberately
// varied at a fixed leading-bit count so an implementation whose work
// tracks set bits is distinguishable from one whose work tracks the
// leading run.
// ==========================================================================

typedef struct {
    uint32_t value;
    const char* note;
} lzc_case_t;

static const lzc_case_t g_cases[] = {
    { 0x7fffffffu, "pos run1  dense " },
    { 0x40000000u, "pos run1  sparse" },
    { 0x3fffffffu, "pos run2  dense " },
    { 0x20000000u, "pos run2  sparse" },
    { 0x1fffffffu, "pos run3  dense " },
    { 0x10000000u, "pos run3  sparse" },
    { 0x0fffffffu, "pos run4  dense " },
    { 0x08000000u, "pos run4  sparse" },
    { 0x07ffffffu, "pos run5  dense " },
    { 0x04000000u, "pos run5  sparse" },
    { 0x03ffffffu, "pos run6  dense " },
    { 0x02000000u, "pos run6  sparse" },
    { 0x01ffffffu, "pos run7  dense " },
    { 0x01000000u, "pos run7  sparse" },
    { 0x00ffffffu, "pos run8  dense " },
    { 0x00800000u, "pos run8  sparse" },
    { 0x007fffffu, "pos run9  dense " },
    { 0x00400000u, "pos run9  sparse" },
    { 0x003fffffu, "pos run10 dense " },
    { 0x00200000u, "pos run10 sparse" },
    { 0x001fffffu, "pos run11 dense " },
    { 0x00100000u, "pos run11 sparse" },
    { 0x000fffffu, "pos run12 dense " },
    { 0x00080000u, "pos run12 sparse" },
    { 0x0007ffffu, "pos run13 dense " },
    { 0x00040000u, "pos run13 sparse" },
    { 0x0003ffffu, "pos run14 dense " },
    { 0x00020000u, "pos run14 sparse" },
    { 0x0001ffffu, "pos run15 dense " },
    { 0x00010000u, "pos run15 sparse" },
    { 0x0000ffffu, "pos run16 dense " },
    { 0x00008000u, "pos run16 sparse" },
    { 0x00007fffu, "pos run17 dense " },
    { 0x00004000u, "pos run17 sparse" },
    { 0x00003fffu, "pos run18 dense " },
    { 0x00002000u, "pos run18 sparse" },
    { 0x00001fffu, "pos run19 dense " },
    { 0x00001000u, "pos run19 sparse" },
    { 0x00000fffu, "pos run20 dense " },
    { 0x00000800u, "pos run20 sparse" },
    { 0x000007ffu, "pos run21 dense " },
    { 0x00000400u, "pos run21 sparse" },
    { 0x000003ffu, "pos run22 dense " },
    { 0x00000200u, "pos run22 sparse" },
    { 0x000001ffu, "pos run23 dense " },
    { 0x00000100u, "pos run23 sparse" },
    { 0x000000ffu, "pos run24 dense " },
    { 0x00000080u, "pos run24 sparse" },
    { 0x0000007fu, "pos run25 dense " },
    { 0x00000040u, "pos run25 sparse" },
    { 0x0000003fu, "pos run26 dense " },
    { 0x00000020u, "pos run26 sparse" },
    { 0x0000001fu, "pos run27 dense " },
    { 0x00000010u, "pos run27 sparse" },
    { 0x0000000fu, "pos run28 dense " },
    { 0x00000008u, "pos run28 sparse" },
    { 0x00000007u, "pos run29 dense " },
    { 0x00000004u, "pos run29 sparse" },
    { 0x00000003u, "pos run30 dense " },
    { 0x00000002u, "pos run30 sparse" },
    { 0x00000001u, "pos run31 dense " },
    { 0x00000001u, "pos run31 sparse" },
    { 0x00000000u, "pos run32 zero  " },
    { 0x80000000u, "neg run1  dense " },
    { 0xbfffffffu, "neg run1  sparse" },
    { 0xc0000000u, "neg run2  dense " },
    { 0xdfffffffu, "neg run2  sparse" },
    { 0xe0000000u, "neg run3  dense " },
    { 0xefffffffu, "neg run3  sparse" },
    { 0xf0000000u, "neg run4  dense " },
    { 0xf7ffffffu, "neg run4  sparse" },
    { 0xf8000000u, "neg run5  dense " },
    { 0xfbffffffu, "neg run5  sparse" },
    { 0xfc000000u, "neg run6  dense " },
    { 0xfdffffffu, "neg run6  sparse" },
    { 0xfe000000u, "neg run7  dense " },
    { 0xfeffffffu, "neg run7  sparse" },
    { 0xff000000u, "neg run8  dense " },
    { 0xff7fffffu, "neg run8  sparse" },
    { 0xff800000u, "neg run9  dense " },
    { 0xffbfffffu, "neg run9  sparse" },
    { 0xffc00000u, "neg run10 dense " },
    { 0xffdfffffu, "neg run10 sparse" },
    { 0xffe00000u, "neg run11 dense " },
    { 0xffefffffu, "neg run11 sparse" },
    { 0xfff00000u, "neg run12 dense " },
    { 0xfff7ffffu, "neg run12 sparse" },
    { 0xfff80000u, "neg run13 dense " },
    { 0xfffbffffu, "neg run13 sparse" },
    { 0xfffc0000u, "neg run14 dense " },
    { 0xfffdffffu, "neg run14 sparse" },
    { 0xfffe0000u, "neg run15 dense " },
    { 0xfffeffffu, "neg run15 sparse" },
    { 0xffff0000u, "neg run16 dense " },
    { 0xffff7fffu, "neg run16 sparse" },
    { 0xffff8000u, "neg run17 dense " },
    { 0xffffbfffu, "neg run17 sparse" },
    { 0xffffc000u, "neg run18 dense " },
    { 0xffffdfffu, "neg run18 sparse" },
    { 0xffffe000u, "neg run19 dense " },
    { 0xffffefffu, "neg run19 sparse" },
    { 0xfffff000u, "neg run20 dense " },
    { 0xfffff7ffu, "neg run20 sparse" },
    { 0xfffff800u, "neg run21 dense " },
    { 0xfffffbffu, "neg run21 sparse" },
    { 0xfffffc00u, "neg run22 dense " },
    { 0xfffffdffu, "neg run22 sparse" },
    { 0xfffffe00u, "neg run23 dense " },
    { 0xfffffeffu, "neg run23 sparse" },
    { 0xffffff00u, "neg run24 dense " },
    { 0xffffff7fu, "neg run24 sparse" },
    { 0xffffff80u, "neg run25 dense " },
    { 0xffffffbfu, "neg run25 sparse" },
    { 0xffffffc0u, "neg run26 dense " },
    { 0xffffffdfu, "neg run26 sparse" },
    { 0xffffffe0u, "neg run27 dense " },
    { 0xffffffefu, "neg run27 sparse" },
    { 0xfffffff0u, "neg run28 dense " },
    { 0xfffffff7u, "neg run28 sparse" },
    { 0xfffffff8u, "neg run29 dense " },
    { 0xfffffffbu, "neg run29 sparse" },
    { 0xfffffffcu, "neg run30 dense " },
    { 0xfffffffdu, "neg run30 sparse" },
    { 0xfffffffeu, "neg run31 dense " },
    { 0xfffffffeu, "neg run31 sparse" },
    { 0xffffffffu, "neg run32 ones  " },
};

#define NCASES ((int)(sizeof(g_cases) / sizeof(g_cases[0])))

// LZCR semantics: count of leading zeroes for a non-negative value,
// count of leading ones for a negative one. Range 1..32.
static uint32_t lzcr_expect(uint32_t v) {
    uint32_t top = (v >> 31) & 1u;
    uint32_t n = 0;
    for (int i = 31; i >= 0; i--) {
        if (((v >> i) & 1u) != top) break;
        n++;
    }
    return n;
}

// A poison whose count is guaranteed to differ from the expected one, so
// a stale read is unambiguous rather than accidentally correct.
static uint32_t poison_for(uint32_t expected) {
    return (expected <= 16) ? 0x00000001u   /* lzcr 31 */
                            : 0x40000000u;  /* lzcr 1  */
}

// ==========================================================================

static uint32_t g_got[MAX_N + 1];
static uint32_t g_warm[MAX_N + 1];
static int g_minN[160];
static int g_n0_correct;
static int g_unstable;
static int g_never_settled;

static void sweep_one(const lzc_case_t* c, int idx, int uncached) {
    uint32_t expected = lzcr_expect(c->value);
    uint32_t poison = poison_for(expected);
    uint32_t poison_lzcr = lzcr_expect(poison);

    // Warm-up pass, discarded. The first execution of each probe body is
    // an icache miss in the cached regime, and a miss stalls the pipeline
    // for exactly the kind of extra cycles that would make a too-small N
    // look sufficient.
    for (int n = 0; n <= MAX_N; n++) {
        lzc_probe_fn f = uncached ? KSEG1(g_probes[n]) : g_probes[n];
        g_warm[n] = f(poison, c->value);
    }

    uint32_t sr = lzc_irq_disable();
    for (int n = 0; n <= MAX_N; n++) {
        lzc_probe_fn f = uncached ? KSEG1(g_probes[n]) : g_probes[n];
        g_got[n] = f(poison, c->value);
    }
    lzc_irq_restore(sr);

    int minN = -1;
    for (int n = 0; n <= MAX_N; n++) {
        if (g_got[n] == expected) { minN = n; break; }
    }
    g_minN[idx] = minN;
    if (minN < 0) g_never_settled++;
    if (g_got[0] == expected) g_n0_correct++;

    int unstable = 0;
    for (int n = 0; n <= MAX_N; n++) {
        if (g_got[n] != g_warm[n]) unstable = 1;
    }
    if (unstable) g_unstable++;

    ramsyscall_printf("LZC %c v=%08x exp=%2d stale=%2d got=[", uncached ? 'U' : 'C',
                      c->value, (int)expected, (int)poison_lzcr);
    for (int n = 0; n <= MAX_N; n++) {
        ramsyscall_printf("%s%d", n ? " " : "", (int)g_got[n]);
    }
    ramsyscall_printf("] minN=%d %s%s\n", minN, c->note, unstable ? " UNSTABLE" : "");

    if (unstable) {
        ramsyscall_printf("LZC %c v=%08x WARMPASS=[", uncached ? 'U' : 'C', c->value);
        for (int n = 0; n <= MAX_N; n++) {
            ramsyscall_printf("%s%d", n ? " " : "", (int)g_warm[n]);
        }
        ramsyscall_printf("]\n");
    }
}

static void run_regime(int uncached) {
    g_n0_correct = 0;
    g_unstable = 0;
    g_never_settled = 0;
    ramsyscall_printf("=== LZCS->LZCR sweep, %s, DRAIN=%d MAX_N=%d ===\n",
                      uncached ? "UNCACHED (kseg1)" : "CACHED (kseg0)", DRAIN, MAX_N);
    for (int i = 0; i < NCASES; i++) sweep_one(&g_cases[i], i, uncached);

    int lo = 99, hi = -1;
    for (int i = 0; i < NCASES; i++) {
        if (g_minN[i] < 0) continue;
        if (g_minN[i] < lo) lo = g_minN[i];
        if (g_minN[i] > hi) hi = g_minN[i];
    }
    ramsyscall_printf("SUMMARY %c minN_range=[%d..%d] n0_correct=%d/%d never_settled=%d unstable=%d\n",
                      uncached ? 'U' : 'C', lo, hi, g_n0_correct, NCASES,
                      g_never_settled, g_unstable);
    ramsyscall_printf("SHAPE %c %s\n", uncached ? 'U' : 'C',
                      (lo == hi) ? "FLAT across input magnitude"
                                 : "VARIES with input magnitude");
}

#endif // GTE_LATENCY_LZCS_HELPERS_DEFINED

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

CESTER_BEFORE_ALL(gte_lzcs_tests,
    lzc_gte_enable();
)

// Sanity: the semantics this whole probe is keyed to, with the tree's
// own 2-nop accessor. If this is wrong nothing below means anything.
CESTER_TEST(lzcs_semantics, gte_lzcs_tests,
    uint32_t out;
    cop2_put(30, 0x00010000); cop2_get(31, out);
    cester_assert_uint_eq(15, out);
    cop2_put(30, 0xfffe0000); cop2_get(31, out);
    cester_assert_uint_eq(15, out);
    cop2_put(30, 0x00000000); cop2_get(31, out);
    cester_assert_uint_eq(32, out);
    cop2_put(30, 0x80000000); cop2_get(31, out);
    cester_assert_uint_eq(1, out);
)

CESTER_TEST(lzcs_sweep_cached, gte_lzcs_tests,
    run_regime(0);
    // Harness liveness, not science: if no N in 0..MAX_N ever reads
    // correctly the sequence is not measuring what it claims.
    cester_assert_int_eq(0, g_never_settled);
    // Negative control. This is an assertion about SILICON, and a
    // failure here is a finding rather than a bug: it would mean the
    // cached sequence never exercises the hazard, and every larger N in
    // the table above is uninformative rather than reassuring.
    cester_assert_int_eq(0, g_n0_correct);
)

CESTER_TEST(lzcs_sweep_uncached, gte_lzcs_tests,
    run_regime(1);
    cester_assert_int_eq(0, g_never_settled);
    // Deliberately NO negative-control assertion here. An uncached
    // opcode fetch is several cycles, so N=0 reading correctly is the
    // documented expectation, not a broken control.
)
