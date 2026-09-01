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

// Shared probe macros and helpers for the GTE input-register latency tests.
//
// For each (instruction, input register), the smallest N such that an
// MTC2 (data) or CTC2 (control) to that register N nops after the GTE op
// does not affect the GTE's output is the practical "instruction slots
// required between the GTE op and the next write to this register".
//
// Each test file (lighting / perspective / color / math / misc) is its
// own ps-exe, includes this header, and emits one CESTER_TEST per
// (instruction, register) probe.

#pragma once

#include "common/hardware/cop2.h"
#include "common/syscalls/syscalls.h"

// clang-format off

// Maximum number of nops to sweep between cop2 op and perturbation.
// All NCCT boundaries observed so far are <= 13; longer instructions
// (NCDT at 44 cycles) push later but inputs are typically read in the
// first half of execution. 32 has comfortable margin and keeps the
// per-test code size manageable so multiple instructions fit in one
// 2 MB ps-exe.
#define MAX_N 32

// A captured GTE output snapshot. We compare the perturbed output's full
// state against the unperturbed baseline; any field changing means the
// perturbation reached the GTE before the latch.
//
// All FIFO entries are captured because triple-vertex instructions
// (RTPT/NCDT/etc.) push three results - perturbing V0 only changes the
// V0 slot (oldest), so comparing only the newest slot misses it.
typedef struct {
    uint32_t rgb0, rgb1, rgb2;
    int32_t  mac0, mac1, mac2, mac3;
    int32_t  ir0, ir1, ir2, ir3;
    uint32_t sxy0, sxy1, sxy2;
    uint32_t sz0, sz1, sz2, sz3;
    uint32_t flag;
} probe_result_t;

// Enable COP2 by setting CU2 in CP0 SR.
static inline void gte_enable(void) {
    uint32_t sr;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr));
    sr |= 0x40000000;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

// Disable / restore CP0.SR.IE (bit 0).
static inline uint32_t irq_disable(void) {
    uint32_t sr_orig, sr_new;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr_orig));
    sr_new = sr_orig & ~1u;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr_new));
    return sr_orig;
}

static inline void irq_restore(uint32_t sr) {
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

// Read the full GTE output state into r. Each cop2_get already pads
// the COP2 read hazard; calling them in sequence is safe.
static inline void read_full_state(probe_result_t* r) {
    cop2_get(20, r->rgb0);
    cop2_get(21, r->rgb1);
    cop2_get(22, r->rgb2);
    int32_t v;
    cop2_get(24, v); r->mac0 = v;
    cop2_get(25, v); r->mac1 = v;
    cop2_get(26, v); r->mac2 = v;
    cop2_get(27, v); r->mac3 = v;
    cop2_get( 8, v); r->ir0 = v;
    cop2_get( 9, v); r->ir1 = v;
    cop2_get(10, v); r->ir2 = v;
    cop2_get(11, v); r->ir3 = v;
    cop2_get(12, r->sxy0);
    cop2_get(13, r->sxy1);
    cop2_get(14, r->sxy2);
    cop2_get(16, r->sz0);
    cop2_get(17, r->sz1);
    cop2_get(18, r->sz2);
    cop2_get(19, r->sz3);
    cop2_getc(31, r->flag);
}

static inline int results_equal(const probe_result_t* a, const probe_result_t* b) {
    return a->rgb0 == b->rgb0 && a->rgb1 == b->rgb1 && a->rgb2 == b->rgb2
        && a->mac0 == b->mac0 && a->mac1 == b->mac1
        && a->mac2 == b->mac2 && a->mac3 == b->mac3
        && a->ir0  == b->ir0  && a->ir1  == b->ir1
        && a->ir2  == b->ir2  && a->ir3  == b->ir3
        && a->sxy0 == b->sxy0 && a->sxy1 == b->sxy1 && a->sxy2 == b->sxy2
        && a->sz0  == b->sz0  && a->sz1  == b->sz1
        && a->sz2  == b->sz2  && a->sz3  == b->sz3
        && a->flag == b->flag;
}

// ==========================================================================
// Probe macros (data-register variant: MTC2)
// ==========================================================================
//
// PROBE_DATA_AT_OFFSET(N, op_imm, dst_reg, canary)
//   cop2 op_imm; <N nops>; mtc2 canary, $dst_reg; <60 nop drain>
//
// PROBE_DATA_BASELINE(op_imm, dst_reg, canary)
//   cop2 op_imm; <80 nop drain>; mtc2 canary, $dst_reg; <4 nops>
//   Canary lands long after the GTE op completes - shape baseline.
//
// PROBE_DATA_SANITY_PRE(op_imm, dst_reg, canary)
//   mtc2 canary, $dst_reg; nop;nop; cop2 op_imm; <80 nop drain>
//   Canary lands BEFORE the GTE op - confirms the canary value would
//   change the result if it landed in time during execution.
//
// op_imm must be a compile-time constant ("i" constraint).

#define PROBE_DATA_AT_OFFSET(N, op_imm, dst_reg, canary) do {              \
    __asm__ volatile(                                                      \
        "cop2 %0\n\t"                                                      \
        ".rept " #N "\n\t"                                                 \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        "mtc2 %1, $" #dst_reg "\n\t"                                       \
        ".rept 60\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

#define PROBE_DATA_BASELINE(op_imm, dst_reg, canary) do {                  \
    __asm__ volatile(                                                      \
        "cop2 %0\n\t"                                                      \
        ".rept 80\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        "mtc2 %1, $" #dst_reg "\n\t"                                       \
        ".rept 4\n\t"                                                      \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

#define PROBE_DATA_SANITY_PRE(op_imm, dst_reg, canary) do {                \
    __asm__ volatile(                                                      \
        "mtc2 %1, $" #dst_reg "\n\t"                                       \
        "nop\n\tnop\n\t"                                                   \
        "cop2 %0\n\t"                                                      \
        ".rept 80\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

// ==========================================================================
// Probe macros (control-register variant: CTC2)
// ==========================================================================

#define PROBE_CTRL_AT_OFFSET(N, op_imm, dst_reg, canary) do {              \
    __asm__ volatile(                                                      \
        "cop2 %0\n\t"                                                      \
        ".rept " #N "\n\t"                                                 \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        "ctc2 %1, $" #dst_reg "\n\t"                                       \
        ".rept 60\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

#define PROBE_CTRL_BASELINE(op_imm, dst_reg, canary) do {                  \
    __asm__ volatile(                                                      \
        "cop2 %0\n\t"                                                      \
        ".rept 80\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        "ctc2 %1, $" #dst_reg "\n\t"                                       \
        ".rept 4\n\t"                                                      \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

#define PROBE_CTRL_SANITY_PRE(op_imm, dst_reg, canary) do {                \
    __asm__ volatile(                                                      \
        "ctc2 %1, $" #dst_reg "\n\t"                                       \
        "nop\n\tnop\n\t"                                                   \
        "cop2 %0\n\t"                                                      \
        ".rept 80\n\t"                                                     \
        "nop\n\t"                                                          \
        ".endr\n\t"                                                        \
        :                                                                  \
        : "i"(op_imm), "r"((uint32_t)(canary))                             \
        : "memory");                                                       \
} while (0)

// ==========================================================================
// Sweep macros - emit MAX_N+1 probes for a single (op, target) pair.
// ==========================================================================
//
// DO_SWEEP_DATA(setup_fn, op_imm, dst_reg, canary, results)
//   For N in 0..MAX_N: setup_fn(); PROBE_DATA_AT_OFFSET(N, ...); record result.
// DO_SWEEP_CTRL: same but with CTC2.
//
// MAX_N must match the iterator below. Increasing MAX_N requires
// extending the unrolled list.

#define DO_SWEEP_DATA(setup_fn, op_imm, dst_reg, canary, results)          \
    do {                                                                   \
        setup_fn(); PROBE_DATA_AT_OFFSET( 0, op_imm, dst_reg, canary); read_full_state(&(results)[ 0]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 1, op_imm, dst_reg, canary); read_full_state(&(results)[ 1]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 2, op_imm, dst_reg, canary); read_full_state(&(results)[ 2]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 3, op_imm, dst_reg, canary); read_full_state(&(results)[ 3]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 4, op_imm, dst_reg, canary); read_full_state(&(results)[ 4]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 5, op_imm, dst_reg, canary); read_full_state(&(results)[ 5]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 6, op_imm, dst_reg, canary); read_full_state(&(results)[ 6]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 7, op_imm, dst_reg, canary); read_full_state(&(results)[ 7]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 8, op_imm, dst_reg, canary); read_full_state(&(results)[ 8]); \
        setup_fn(); PROBE_DATA_AT_OFFSET( 9, op_imm, dst_reg, canary); read_full_state(&(results)[ 9]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(10, op_imm, dst_reg, canary); read_full_state(&(results)[10]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(11, op_imm, dst_reg, canary); read_full_state(&(results)[11]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(12, op_imm, dst_reg, canary); read_full_state(&(results)[12]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(13, op_imm, dst_reg, canary); read_full_state(&(results)[13]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(14, op_imm, dst_reg, canary); read_full_state(&(results)[14]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(15, op_imm, dst_reg, canary); read_full_state(&(results)[15]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(16, op_imm, dst_reg, canary); read_full_state(&(results)[16]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(17, op_imm, dst_reg, canary); read_full_state(&(results)[17]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(18, op_imm, dst_reg, canary); read_full_state(&(results)[18]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(19, op_imm, dst_reg, canary); read_full_state(&(results)[19]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(20, op_imm, dst_reg, canary); read_full_state(&(results)[20]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(21, op_imm, dst_reg, canary); read_full_state(&(results)[21]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(22, op_imm, dst_reg, canary); read_full_state(&(results)[22]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(23, op_imm, dst_reg, canary); read_full_state(&(results)[23]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(24, op_imm, dst_reg, canary); read_full_state(&(results)[24]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(25, op_imm, dst_reg, canary); read_full_state(&(results)[25]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(26, op_imm, dst_reg, canary); read_full_state(&(results)[26]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(27, op_imm, dst_reg, canary); read_full_state(&(results)[27]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(28, op_imm, dst_reg, canary); read_full_state(&(results)[28]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(29, op_imm, dst_reg, canary); read_full_state(&(results)[29]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(30, op_imm, dst_reg, canary); read_full_state(&(results)[30]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(31, op_imm, dst_reg, canary); read_full_state(&(results)[31]); \
        setup_fn(); PROBE_DATA_AT_OFFSET(32, op_imm, dst_reg, canary); read_full_state(&(results)[32]); \
    } while (0)

#define DO_SWEEP_CTRL(setup_fn, op_imm, dst_reg, canary, results)          \
    do {                                                                   \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 0, op_imm, dst_reg, canary); read_full_state(&(results)[ 0]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 1, op_imm, dst_reg, canary); read_full_state(&(results)[ 1]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 2, op_imm, dst_reg, canary); read_full_state(&(results)[ 2]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 3, op_imm, dst_reg, canary); read_full_state(&(results)[ 3]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 4, op_imm, dst_reg, canary); read_full_state(&(results)[ 4]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 5, op_imm, dst_reg, canary); read_full_state(&(results)[ 5]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 6, op_imm, dst_reg, canary); read_full_state(&(results)[ 6]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 7, op_imm, dst_reg, canary); read_full_state(&(results)[ 7]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 8, op_imm, dst_reg, canary); read_full_state(&(results)[ 8]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET( 9, op_imm, dst_reg, canary); read_full_state(&(results)[ 9]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(10, op_imm, dst_reg, canary); read_full_state(&(results)[10]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(11, op_imm, dst_reg, canary); read_full_state(&(results)[11]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(12, op_imm, dst_reg, canary); read_full_state(&(results)[12]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(13, op_imm, dst_reg, canary); read_full_state(&(results)[13]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(14, op_imm, dst_reg, canary); read_full_state(&(results)[14]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(15, op_imm, dst_reg, canary); read_full_state(&(results)[15]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(16, op_imm, dst_reg, canary); read_full_state(&(results)[16]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(17, op_imm, dst_reg, canary); read_full_state(&(results)[17]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(18, op_imm, dst_reg, canary); read_full_state(&(results)[18]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(19, op_imm, dst_reg, canary); read_full_state(&(results)[19]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(20, op_imm, dst_reg, canary); read_full_state(&(results)[20]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(21, op_imm, dst_reg, canary); read_full_state(&(results)[21]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(22, op_imm, dst_reg, canary); read_full_state(&(results)[22]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(23, op_imm, dst_reg, canary); read_full_state(&(results)[23]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(24, op_imm, dst_reg, canary); read_full_state(&(results)[24]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(25, op_imm, dst_reg, canary); read_full_state(&(results)[25]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(26, op_imm, dst_reg, canary); read_full_state(&(results)[26]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(27, op_imm, dst_reg, canary); read_full_state(&(results)[27]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(28, op_imm, dst_reg, canary); read_full_state(&(results)[28]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(29, op_imm, dst_reg, canary); read_full_state(&(results)[29]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(30, op_imm, dst_reg, canary); read_full_state(&(results)[30]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(31, op_imm, dst_reg, canary); read_full_state(&(results)[31]); \
        setup_fn(); PROBE_CTRL_AT_OFFSET(32, op_imm, dst_reg, canary); read_full_state(&(results)[32]); \
    } while (0)

// ==========================================================================
// Reporting
// ==========================================================================
// Print sweep results in a fixed format that downstream scripts can parse:
//
//   === <name> ===
//   baseline    RGB=(...) MAC0=... MAC=(...) IR0=... IR=(...) FLAG=...
//   sanity-pre  ... DIFFERS_OK | *** SAME_AS_BASELINE_BUG ***
//   N=NN ...
//   === <name> boundary: N=NN ===

static void report_sweep(const char* name,
                         const probe_result_t* baseline,
                         const probe_result_t* sanity_pre,
                         const probe_result_t results[MAX_N + 1]) {
    ramsyscall_printf("=== %s ===\n", name);
    ramsyscall_printf("baseline    RGB=(0x%08x,0x%08x,0x%08x) MAC0=%d MAC=(%d,%d,%d) IR0=%d IR=(%d,%d,%d) FLAG=0x%08x\n",
                      baseline->rgb0, baseline->rgb1, baseline->rgb2,
                      baseline->mac0, baseline->mac1, baseline->mac2, baseline->mac3,
                      baseline->ir0, baseline->ir1, baseline->ir2, baseline->ir3,
                      baseline->flag);
    int sanity_differs = !results_equal(baseline, sanity_pre);
    ramsyscall_printf("sanity-pre  RGB=(0x%08x,0x%08x,0x%08x) MAC0=%d MAC=(%d,%d,%d) IR0=%d IR=(%d,%d,%d) FLAG=0x%08x %s\n",
                      sanity_pre->rgb0, sanity_pre->rgb1, sanity_pre->rgb2,
                      sanity_pre->mac0, sanity_pre->mac1, sanity_pre->mac2, sanity_pre->mac3,
                      sanity_pre->ir0, sanity_pre->ir1, sanity_pre->ir2, sanity_pre->ir3,
                      sanity_pre->flag,
                      sanity_differs ? "DIFFERS_OK" : "*** SAME_AS_BASELINE_BUG ***");
    int boundary = -1;
    for (int n = 0; n <= MAX_N; n++) {
        int matches = results_equal(baseline, &results[n]);
        ramsyscall_printf("N=%2d RGB=(0x%08x,0x%08x,0x%08x) MAC=(%d,%d,%d) IR=(%d,%d,%d) FLAG=0x%08x %s\n",
                          n,
                          results[n].rgb0, results[n].rgb1, results[n].rgb2,
                          results[n].mac1, results[n].mac2, results[n].mac3,
                          results[n].ir1, results[n].ir2, results[n].ir3,
                          results[n].flag,
                          matches ? "MATCH" : "diff");
        if (matches && boundary < 0) boundary = n;
    }
    ramsyscall_printf("=== %s boundary: N=%d ===\n", name, boundary);
}

// ==========================================================================
// Test-body helpers (each probe is a single CESTER_TEST that calls these)
// ==========================================================================
//
// MAKE_DATA_TEST(test_name, scene_setup, op_imm, dst_reg, canary, label)
//   Emits a CESTER_TEST that runs baseline + sanity_pre + warmup +
//   measurement sweeps for an MTC2 (data) probe.

#define MAKE_DATA_TEST(test_name, scene_setup, op_imm, dst_reg, canary, label) \
CESTER_TEST(test_name, gte_latency_tests,                                  \
    static probe_result_t baseline, sanity_pre;                            \
    static probe_result_t warmup[MAX_N + 1];                               \
    static probe_result_t results[MAX_N + 1];                              \
    scene_setup();                                                         \
    PROBE_DATA_BASELINE(op_imm, dst_reg, canary);                          \
    read_full_state(&baseline);                                            \
    scene_setup();                                                         \
    PROBE_DATA_SANITY_PRE(op_imm, dst_reg, canary);                        \
    read_full_state(&sanity_pre);                                          \
    uint32_t saved_sr = irq_disable();                                     \
    DO_SWEEP_DATA(scene_setup, op_imm, dst_reg, canary, warmup);           \
    DO_SWEEP_DATA(scene_setup, op_imm, dst_reg, canary, results);          \
    irq_restore(saved_sr);                                                 \
    report_sweep(label, &baseline, &sanity_pre, results);                  \
    cester_assert_true(!results_equal(&baseline, &sanity_pre));            \
)

#define MAKE_CTRL_TEST(test_name, scene_setup, op_imm, dst_reg, canary, label) \
CESTER_TEST(test_name, gte_latency_tests,                                  \
    static probe_result_t baseline, sanity_pre;                            \
    static probe_result_t warmup[MAX_N + 1];                               \
    static probe_result_t results[MAX_N + 1];                              \
    scene_setup();                                                         \
    PROBE_CTRL_BASELINE(op_imm, dst_reg, canary);                          \
    read_full_state(&baseline);                                            \
    scene_setup();                                                         \
    PROBE_CTRL_SANITY_PRE(op_imm, dst_reg, canary);                        \
    read_full_state(&sanity_pre);                                          \
    uint32_t saved_sr = irq_disable();                                     \
    DO_SWEEP_CTRL(scene_setup, op_imm, dst_reg, canary, warmup);           \
    DO_SWEEP_CTRL(scene_setup, op_imm, dst_reg, canary, results);          \
    irq_restore(saved_sr);                                                 \
    report_sweep(label, &baseline, &sanity_pre, results);                  \
    cester_assert_true(!results_equal(&baseline, &sanity_pre));            \
)
