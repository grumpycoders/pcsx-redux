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

/* D-Cache / Scratchpad empirical tests for BIU_CONFIG bits 3, 4-5, and 7.
 *
 * Characterizes the "d-cache mode" reached by setting bit 7 (DS) and
 * clearing bit 3 (RAM). In that mode the scratchpad SRAM is repurposed as
 * a tag-less data cache: every cached-segment load is a tag mismatch and
 * fills scratchpad at slot (load_byte_addr >> 2) & 0xff with the loaded
 * word. The suite verifies the exact mapping, sub-word load behavior,
 * KSEG1 bypass, store-side behavior, BIU bit interactions, and several
 * inverse-mode controls. See psx-spx memorycontrol.md for the documented
 * behavior.
 */

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

/* BIU bit construction. */
#define BIU_BASE             0x0001e900u
#define BIT_RAM              (1u << 3)
#define BIT_DS               (1u << 7)
#define DBLKSZ(n)            (((n) & 3u) << 4)

#define BIU_NORMAL           (BIU_BASE | BIT_RAM | BIT_DS)
#define BIU_RAM_ONLY         (BIU_BASE | BIT_RAM)
#define BIU_DS_ONLY(dblksz)  (BIU_BASE | BIT_DS | DBLKSZ(dblksz))
#define BIU_NEITHER          (BIU_BASE)

/* Scratchpad. */
#define SCRATCHPAD_BASE      0x1f800000u
#define SCRATCHPAD_WORDS     256

/* Cached test data buffer at 1 MiB into RAM, well above the PS-EXE area
   (0x80010000) and below the stack. 4 KiB = 1024 words = 4x scratchpad
   aliasing window. */
#define TEST_DATA_KSEG0      0x80100000u
#define TEST_DATA_KSEG1      0xa0100000u
#define TEST_DATA_WORDS      1024

#define BASE_PATTERN         0x5a000000u

/* Hardware mapping: a load at byte address A stores its result at
 * sp[(A/4) & 0xff]. */
#define SP_SLOT_FOR_WORD(wi) ((wi) & 0xffu)

CESTER_BODY(
    extern uint32_t dcache_get_biu(void);
    extern void     dcache_set_biu(uint32_t value);
    extern uint32_t dcache_run_reads(uint32_t biu_value, uint32_t src, uint32_t count);
    extern uint32_t dcache_run_reads_strided(uint32_t biu_value, uint32_t src,
                                             uint32_t count, uint32_t stride);
    extern uint32_t dcache_run_reads_drained(uint32_t biu_value, uint32_t src,
                                             uint32_t count, uint32_t drain_nops);
    extern uint32_t dcache_run_reads_swc(uint32_t biu_value, uint32_t src, uint32_t count);
    extern void     dcache_run_writes(uint32_t biu_value, uint32_t dst, uint32_t count,
                                      uint32_t base_pattern);
    extern uint32_t dcache_run_byte_reads(uint32_t biu_value, uint32_t src, uint32_t count);
    extern uint32_t dcache_run_half_reads(uint32_t biu_value, uint32_t src, uint32_t count);
    extern void     dcache_run_writes_at_sp_addr(uint32_t biu_value, uint32_t sp_off,
                                                 uint32_t count, uint32_t base);
    extern uint32_t dcache_run_reads_at_sp_addr(uint32_t biu_value, uint32_t sp_off,
                                                uint32_t count);
    extern void     dcache_zero_scratchpad(void);
    extern void     dcache_dump_scratchpad(uint32_t *out_256_words);
    extern void     dcache_fill_pattern(uint32_t dst, uint32_t count, uint32_t base_pattern);

    static int      s_interruptsWereEnabled;
    static uint32_t s_dump[SCRATCHPAD_WORDS];

    static int sp_nonzero_count(const uint32_t *dump) {
        int n = 0;
        for (int i = 0; i < SCRATCHPAD_WORDS; i++) if (dump[i] != 0) n++;
        return n;
    }

    static void sp_signature(const char *tag, const uint32_t *dump) {
        int first = -1, last = -1, n = 0;
        for (int i = 0; i < SCRATCHPAD_WORDS; i++) {
            if (dump[i] != 0) { if (first < 0) first = i; last = i; n++; }
        }
        ramsyscall_printf("  [%s] nonzero=%d first=%d last=%d", tag, n, first, last);
        if (first >= 0) {
            ramsyscall_printf(" sp[%d]=%08lx sp[%d]=%08lx",
                              first, dump[first], last, dump[last]);
        }
        ramsyscall_printf("\n");
    }

    /* Print every nonzero scratchpad slot (limit prevents runaway prints). */
    static void sp_dump_nonzero(const char *tag, const uint32_t *dump, int limit) {
        ramsyscall_printf("  [%s] nonzero slots:\n", tag);
        int printed = 0;
        for (int i = 0; i < SCRATCHPAD_WORDS && printed < limit; i++) {
            if (dump[i] != 0) {
                ramsyscall_printf("    sp[%3d] = 0x%08lx\n", i, dump[i]);
                printed++;
            }
        }
        if (printed == limit) ramsyscall_printf("    ... (truncated at %d)\n", limit);
    }
)

CESTER_BEFORE_ALL(dcache_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    syscall_flushCache();
    dcache_fill_pattern(TEST_DATA_KSEG0, TEST_DATA_WORDS, BASE_PATTERN);
)

CESTER_AFTER_ALL(dcache_tests,
    dcache_set_biu(BIU_NORMAL);
    syscall_flushCache();
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

CESTER_BEFORE_EACH(dcache_tests, testname, testindex,
)

CESTER_AFTER_EACH(dcache_tests, testname, testindex,
)

/* =========================================================================
 * SECTION A. Sanity and baseline.
 * ========================================================================= */

CESTER_TEST(a01_baseline_biu, dcache_tests,
    uint32_t biu = dcache_get_biu();
    ramsyscall_printf("=== a01_baseline_biu ===\n");
    ramsyscall_printf("  BIU_CONFIG = 0x%08lx (expected 0x%08lx)\n",
                      biu, (uint32_t)BIU_NORMAL);
    cester_assert_uint_eq((uint32_t)BIU_NORMAL, biu);
)

/* =========================================================================
 * SECTION B. The sp[0] leak. Where does the persistent 0x20 come from?
 * ========================================================================= */

CESTER_TEST(b01_sp_initial_state, dcache_tests,
    /* Dump scratchpad before doing anything. If sp[0] is already 0x20 here,
       it's a boot-time / runtime initialization artifact, not our doing. */
    ramsyscall_printf("=== b01_sp_initial_state ===\n");
    dcache_dump_scratchpad(s_dump);
    sp_signature("initial", s_dump);
    sp_dump_nonzero("initial", s_dump, 8);
)

CESTER_TEST(b02_sp_after_zero, dcache_tests,
    ramsyscall_printf("=== b02_sp_after_zero ===\n");
    dcache_zero_scratchpad();
    dcache_dump_scratchpad(s_dump);
    sp_signature("post-zero", s_dump);
    if (sp_nonzero_count(s_dump) > 0) sp_dump_nonzero("post-zero", s_dump, 8);

    /* Sanity: zero followed by dump leaves scratchpad clean. */
    cester_assert_uint_eq(0, sp_nonzero_count(s_dump));
)

/* =========================================================================
 * SECTION C. Single-word mapping. Read EXACTLY one word at carefully chosen
 * addresses. Dump full scratchpad. Print every nonzero slot. With pipeline
 * drain, every read should produce exactly one fill. The mapping
 * (read_addr -> sp_slot) becomes self-evident from the printed data.
 * ========================================================================= */

CESTER_TEST(c01_single_word_mapping, dcache_tests,
    ramsyscall_printf("=== c01_single_word_mapping ===\n");

    /* Test addresses span the relevant bit positions and the wraparound. */
    static const uint32_t addrs[] = {
        TEST_DATA_KSEG0 + 0,        /* word 0   - expect sp[1]   */
        TEST_DATA_KSEG0 + 4,        /* word 1   - expect sp[2]   */
        TEST_DATA_KSEG0 + 8,        /* word 2   - expect sp[3]   */
        TEST_DATA_KSEG0 + 16,       /* word 4   - expect sp[5]   */
        TEST_DATA_KSEG0 + 64,       /* word 16  - expect sp[17]  */
        TEST_DATA_KSEG0 + 0x100,    /* word 64  - expect sp[65]  */
        TEST_DATA_KSEG0 + 0x1FC,    /* word 127 - expect sp[128] */
        TEST_DATA_KSEG0 + 0x200,    /* word 128 - expect sp[129] */
        TEST_DATA_KSEG0 + 0x3F8,    /* word 254 - expect sp[255] */
        TEST_DATA_KSEG0 + 0x3FC,    /* word 255 - WRAP, expect sp[0] */
        TEST_DATA_KSEG0 + 0x400,    /* word 256 - expect sp[1]   */
        TEST_DATA_KSEG0 + 0x800,    /* word 512 - expect sp[1]   */
    };
    int n = sizeof(addrs) / sizeof(addrs[0]);

    for (int k = 0; k < n; k++) {
        dcache_zero_scratchpad();

        /* Read exactly 1 word with 64 cycles of pipeline drain to ensure
           the fill lands. */
        dcache_run_reads_drained(BIU_DS_ONLY(0), addrs[k], 1, 64);

        dcache_dump_scratchpad(s_dump);

        uint32_t word_idx = (addrs[k] - TEST_DATA_KSEG0) / 4;
        uint32_t expected_pattern = BASE_PATTERN ^ word_idx;
        uint32_t expected_slot = SP_SLOT_FOR_WORD(word_idx);

        ramsyscall_printf("  read 0x%08lx (word %3lu, expect sp[%3lu]=0x%08lx):\n",
                          addrs[k], word_idx, expected_slot, expected_pattern);
        sp_dump_nonzero("", s_dump, 4);
    }
)

/* =========================================================================
 * SECTION D. Pipeline drain. Vary the number of nops between the last
 * load and the BIU restore. All values should produce identical fills -
 * the d-cache miss-fill is not racing the BIU restore.
 * ========================================================================= */

CESTER_TEST(d01_pipeline_drain_sweep, dcache_tests,
    ramsyscall_printf("=== d01_pipeline_drain_sweep ===\n");

    static const uint32_t drain_values[] = { 0, 1, 2, 4, 8, 16, 32 };
    int n = sizeof(drain_values) / sizeof(drain_values[0]);

    const uint32_t COUNT = 4;

    for (int k = 0; k < n; k++) {
        dcache_zero_scratchpad();
        dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0, COUNT, drain_values[k]);
        dcache_dump_scratchpad(s_dump);

        ramsyscall_printf("  drain=%lu, count=%lu reads:\n", drain_values[k], COUNT);
        sp_dump_nonzero("", s_dump, 8);
    }
)

/* =========================================================================
 * SECTION E. KSEG1 reads should bypass the d-cache entirely. With bit 7
 * set, reading from the uncached mirror of the test data should NOT fill
 * scratchpad.
 * ========================================================================= */

CESTER_TEST(e01_kseg1_reads_no_fill, dcache_tests,
    ramsyscall_printf("=== e01_kseg1_reads_no_fill ===\n");

    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG1, 64, 16);
    dcache_dump_scratchpad(s_dump);

    sp_signature("kseg1-ds", s_dump);
    if (sp_nonzero_count(s_dump) > 0) sp_dump_nonzero("kseg1-ds", s_dump, 8);

    /* No assertion - characterize first, decide later. */
)

/* =========================================================================
 * SECTION F. Repeated read at the same address. Does the second read also
 * fill (since tag never matches), or does it serve from the now-populated
 * scratchpad slot (apparent cache hit)?
 *
 * With known data at addr X (pattern[wi]), read X twice. If the second read
 * is a "hit", scratchpad slot still equals pattern[wi]. If the second read
 * is also a miss-fill, scratchpad slot still equals pattern[wi] - same data,
 * indistinguishable. So we modify the data BETWEEN the two reads to tell
 * them apart: first read returns pattern A and fills sp with A; we then
 * overwrite the RAM word with a different pattern B via uncached store;
 * second read either returns A (cache hit) or B (cache miss).
 * ========================================================================= */

CESTER_TEST(f01_repeated_read_behavior, dcache_tests,
    ramsyscall_printf("=== f01_repeated_read_behavior ===\n");

    const uint32_t addr   = TEST_DATA_KSEG0 + 0;
    const uint32_t addr_u = TEST_DATA_KSEG1 + 0;
    const uint32_t pat_a  = 0xa1a1a1a1u;
    const uint32_t pat_b  = 0xb2b2b2b2u;

    volatile uint32_t *unc = (volatile uint32_t *)addr_u;

    dcache_zero_scratchpad();
    *unc = pat_a;
    dcache_run_reads_drained(BIU_DS_ONLY(0), addr, 1, 64);
    dcache_dump_scratchpad(s_dump);
    uint32_t after_first = s_dump[0];   /* direct mapping: sp[0] from word 0 */
    ramsyscall_printf("  after 1st read (expect 0x%08lx): sp[0] = 0x%08lx\n",
                      pat_a, after_first);

    /* Overwrite RAM via uncached mirror (no cache invalidation). */
    *unc = pat_b;

    /* Second read with bit 7 still set - what do we get? */
    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), addr, 1, 64);
    dcache_dump_scratchpad(s_dump);
    uint32_t after_second = s_dump[0];
    ramsyscall_printf("  after 2nd read (RAM now 0x%08lx): sp[0] = 0x%08lx\n",
                      pat_b, after_second);

    /* Restore the buffer's pattern for subsequent tests. */
    *unc = BASE_PATTERN ^ 0u;
)

/* =========================================================================
 * SECTION G. Stores in d-cache mode. Write to RAM with bit 7 set; check if
 * the store also propagates to scratchpad (write-through-on-miss?).
 * ========================================================================= */

CESTER_TEST(g01_stores_in_dcache_mode, dcache_tests,
    ramsyscall_printf("=== g01_stores_in_dcache_mode ===\n");

    dcache_zero_scratchpad();
    /* Issue 16 stores at 16 different word addresses (low-10-bit offsets
       0..0x3C). Pattern 0xc0000000 ^ index. Drain in the probe. */
    dcache_run_writes(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 16, 0xc0000000u);
    dcache_dump_scratchpad(s_dump);

    sp_signature("ds-only-stores", s_dump);
    sp_dump_nonzero("ds-only-stores", s_dump, 16);

    /* Restore pattern for downstream tests. */
    dcache_fill_pattern(TEST_DATA_KSEG0, TEST_DATA_WORDS, BASE_PATTERN);
)

/* =========================================================================
 * SECTION H. Full 256-word sweep. Reads words 0..255 from the test buffer
 * and asserts sp[wi] == pattern[wi] for every wi (the bijective case
 * before any modulo wraparound kicks in).
 * ========================================================================= */

CESTER_TEST(h01_mapping_full_sweep, dcache_tests,
    ramsyscall_printf("=== h01_mapping_full_sweep ===\n");

    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0,
                             SCRATCHPAD_WORDS, 64);
    dcache_dump_scratchpad(s_dump);

    int matches = 0, mismatches = 0;
    for (uint32_t wi = 0; wi < SCRATCHPAD_WORDS; wi++) {
        uint32_t slot = SP_SLOT_FOR_WORD(wi);
        uint32_t expected = BASE_PATTERN ^ wi;
        if (s_dump[slot] == expected) matches++; else mismatches++;
    }
    ramsyscall_printf("  matches=%d mismatches=%d (out of %d)\n",
                      matches, mismatches, SCRATCHPAD_WORDS);
    sp_signature("sweep+drain", s_dump);

    cester_assert_uint_eq(SCRATCHPAD_WORDS, (uint32_t)matches);
)

/* =========================================================================
 * SECTION I. Stride probes. Stride-16 reads at line-aligned addresses
 * fill sp[0, 4, 8, ..., 252]. Confirms direct mapping at line stride.
 * ========================================================================= */

CESTER_TEST(i01_stride16_at_offset_zero, dcache_tests,
    ramsyscall_printf("=== i01_stride16_at_offset_zero ===\n");

    dcache_zero_scratchpad();
    dcache_run_reads_strided(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 64, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("stride=16", s_dump);

    /* Direct mapping predicts sp[0, 4, 8, ..., 252] populated, others zero. */
    int at_offset_zero = 0, others = 0;
    for (int i = 0; i < SCRATCHPAD_WORDS; i++) {
        if (s_dump[i] == 0) continue;
        if ((i & 3) == 0) at_offset_zero++;
        else others++;
    }
    ramsyscall_printf("  hits at i%%4==0: %d (expected 64)\n", at_offset_zero);
    ramsyscall_printf("  hits at other slots: %d (expected 0)\n", others);

    cester_assert_uint_eq(64u, (uint32_t)at_offset_zero);
    cester_assert_uint_eq(0u, (uint32_t)others);
)

/* =========================================================================
 * SECTION J. DBLKSZ sweep with corrected mapping.
 * ========================================================================= */

CESTER_TEST(j01_dblksz_sweep, dcache_tests,
    ramsyscall_printf("=== j01_dblksz_sweep ===\n");

    for (int dblksz = 0; dblksz < 4; dblksz++) {
        dcache_zero_scratchpad();
        dcache_run_reads_strided(BIU_DS_ONLY(dblksz), TEST_DATA_KSEG0, 64, 16);
        dcache_dump_scratchpad(s_dump);

        char tag[16];
        tag[0] = 'd'; tag[1] = 'b'; tag[2] = 'l'; tag[3] = 'k';
        tag[4] = '='; tag[5] = (char)('0' + dblksz); tag[6] = '\0';
        sp_signature(tag, s_dump);

        int at_offset_zero = 0;
        for (int i = 0; i < SCRATCHPAD_WORDS; i++) {
            if (s_dump[i] != 0 && (i & 3) == 0) at_offset_zero++;
        }
        ramsyscall_printf("    hits at i%%4==0: %d\n", at_offset_zero);
    }
)

/* =========================================================================
 * SECTION K. Inverse-mode controls. RAM-only and neither-bit-set should
 * not fill scratchpad in any mode.
 * ========================================================================= */

CESTER_TEST(k01_ram_only_no_fill, dcache_tests,
    ramsyscall_printf("=== k01_ram_only_no_fill ===\n");
    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_RAM_ONLY, TEST_DATA_KSEG0, SCRATCHPAD_WORDS, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("ram-only", s_dump);
    if (sp_nonzero_count(s_dump) > 0) sp_dump_nonzero("ram-only", s_dump, 4);
)

CESTER_TEST(k02_neither_no_fill, dcache_tests,
    ramsyscall_printf("=== k02_neither_no_fill ===\n");
    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_NEITHER, TEST_DATA_KSEG0, SCRATCHPAD_WORDS, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("neither", s_dump);
    if (sp_nonzero_count(s_dump) > 0) sp_dump_nonzero("neither", s_dump, 4);
)

/* =========================================================================
 * SECTION L. SwC + DS-only. Speculative; just dump.
 * ========================================================================= */

CESTER_TEST(l01_swc_with_ds_only, dcache_tests,
    ramsyscall_printf("=== l01_swc_with_ds_only ===\n");
    dcache_zero_scratchpad();
    dcache_run_reads_swc(BIU_DS_ONLY(0), TEST_DATA_KSEG0, SCRATCHPAD_WORDS);
    dcache_dump_scratchpad(s_dump);
    sp_signature("swc+ds", s_dump);

    int matches = 0;
    for (uint32_t wi = 0; wi < SCRATCHPAD_WORDS; wi++) {
        uint32_t slot = SP_SLOT_FOR_WORD(wi);
        uint32_t expected = BASE_PATTERN ^ wi;
        if (s_dump[slot] == expected) matches++;
    }
    ramsyscall_printf("  mapping matches under SwC: %d / %d\n",
                      matches, SCRATCHPAD_WORDS);
)

/* =========================================================================
 * SECTION M. Address aliasing. Reads from two different upper-bit
 * addresses with the same low 10 bits both land in the same scratchpad
 * slot, confirming the tag-hardwired-to-upper-bits mechanism.
 * ========================================================================= */

CESTER_TEST(m01_address_aliasing, dcache_tests,
    ramsyscall_printf("=== m01_address_aliasing ===\n");

    /* TEST_DATA_KSEG0 = 0x80100000. ALT shares the same low 10 bits.
       Pre-stage ALT with a distinct base pattern at word 0 (= 0xa5a5a5a5). */
    const uint32_t ALT       = 0x80200000u;
    const uint32_t ALT_KSEG1 = 0xa0200000u;
    volatile uint32_t *alt_unc = (volatile uint32_t *)ALT_KSEG1;
    *alt_unc = 0xa5a5a5a5u;

    /* Direct mapping: read at word 0 fills sp[0]. */
    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 1, 64);
    dcache_dump_scratchpad(s_dump);
    uint32_t a = s_dump[0];
    ramsyscall_printf("  read @0x%08lx -> sp[0] = 0x%08lx (expected 0x%08lx)\n",
                      (uint32_t)TEST_DATA_KSEG0, a, BASE_PATTERN ^ 0);

    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), ALT, 1, 64);
    dcache_dump_scratchpad(s_dump);
    uint32_t b = s_dump[0];
    ramsyscall_printf("  read @0x%08lx -> sp[0] = 0x%08lx (expected 0xa5a5a5a5)\n",
                      ALT, b);

    cester_assert_uint_eq(BASE_PATTERN ^ 0u, a);
    cester_assert_uint_eq(0xa5a5a5a5u, b);
)

/* =========================================================================
 * SECTION N. sp[0] survival under various BIU modes. Confirms that
 * scratchpad SRAM is plain RAM: volatile writes stick, sentinels survive
 * read probes that don't map to sp[0], and zero_scratchpad fully clears
 * the SRAM.
 * ========================================================================= */

CESTER_TEST(n01_volatile_write_to_sp0, dcache_tests,
    ramsyscall_printf("=== n01_volatile_write_to_sp0 ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    /* BIU is NORMAL (RAM=1, DS=1). Plain scratchpad mode. */
    sp[0] = 0xcafebabeu;
    uint32_t readback = sp[0];
    ramsyscall_printf("  wrote 0xcafebabe to sp[0], read back 0x%08lx\n", readback);
    cester_assert_uint_eq(0xcafebabeu, readback);

    /* Now dump via the assembly probe (also runs in BIU=NORMAL path). */
    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  via dump probe: sp[0] = 0x%08lx\n", s_dump[0]);
    cester_assert_uint_eq(0xcafebabeu, s_dump[0]);

    /* Tidy up. */
    sp[0] = 0;
)

CESTER_TEST(n02_zero_then_volatile_write_sp0, dcache_tests,
    ramsyscall_printf("=== n02_zero_then_volatile_write_sp0 ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    dcache_zero_scratchpad();
    ramsyscall_printf("  after zero: sp[0] = 0x%08lx\n", sp[0]);

    sp[0] = 0xdeadbeefu;
    ramsyscall_printf("  after volatile write: sp[0] = 0x%08lx\n", sp[0]);

    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  via dump probe: sp[0] = 0x%08lx\n", s_dump[0]);

    /* If volatile write sticks but assembly zero doesn't, the issue is in
       the assembly zero_scratchpad routine, not in sp[0]'s nature. */
    cester_assert_uint_eq(0xdeadbeefu, s_dump[0]);

    sp[0] = 0;
)

CESTER_TEST(n03_sp0_survives_dcache_fill, dcache_tests,
    /* Pre-write sp[0] with a sentinel via volatile (BIU=NORMAL).
     * Then run a single read at word 255 (whose +1 wraps to sp[0]) with
     * bit 7 only.
     * If sp[0] reads back as the sentinel: d-cache fill simply doesn't
     *   touch sp[0] (write-protected against the miss-fill path).
     * If sp[0] reads back as the read's pattern (0x5a0000ff): the fill
     *   DID land but our earlier observation of "0x20 leak" was somehow
     *   masking it.
     * If sp[0] reads back as 0x20 (or another mystery value): the d-cache
     *   miss-fill path actively overwrites sp[0] with hardware status.
     */
    ramsyscall_printf("=== n03_sp0_survives_dcache_fill ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    sp[0] = 0xfeedf00du;
    ramsyscall_printf("  pre: sp[0] = 0x%08lx\n", sp[0]);

    /* Read word 255 with bit 7 only. +1 wrap target = sp[0]. */
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0 + 0x3FC, 1, 64);

    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  post (read word 255 with DS only): sp[0] = 0x%08lx\n",
                      s_dump[0]);
    /* No assertion - this is a measurement. */

    sp[0] = 0;
)

CESTER_TEST(n04_sp0_after_kseg1_read, dcache_tests,
    /* Pre-write sentinel, then read from KSEG1 (uncached) which should
       NOT engage d-cache. Does sp[0] survive untouched? */
    ramsyscall_printf("=== n04_sp0_after_kseg1_read ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    sp[0] = 0xfeedf00du;
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG1, 16, 16);
    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  sp[0] after kseg1 reads: 0x%08lx\n", s_dump[0]);

    sp[0] = 0;
)

CESTER_TEST(n05_sp0_with_ram_only, dcache_tests,
    /* Sentinel sp[0]. Run reads with RAM-only mode (bit 7 clear). Does
       sp[0] survive? In this mode there's no d-cache so no miss-fills. */
    ramsyscall_printf("=== n05_sp0_with_ram_only ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    sp[0] = 0xfeedf00du;
    dcache_run_reads_drained(BIU_RAM_ONLY, TEST_DATA_KSEG0, 16, 16);
    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  sp[0] after RAM-only reads: 0x%08lx\n", s_dump[0]);

    sp[0] = 0;
)

CESTER_TEST(n06_sp0_with_neither, dcache_tests,
    /* Sentinel. Run reads with both bits clear. sp[0] should survive. */
    ramsyscall_printf("=== n06_sp0_with_neither ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    sp[0] = 0xfeedf00du;
    dcache_run_reads_drained(BIU_NEITHER, TEST_DATA_KSEG0, 16, 16);
    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  sp[0] after BIU-neither reads: 0x%08lx\n", s_dump[0]);

    sp[0] = 0;
)

CESTER_TEST(n07_sp0_observation_after_count_reads, dcache_tests,
    /* The "0x20 ↔ 0x10 ↔ random" sp[0] values across tests look like state
     * snapshots related to count or address. Vary count and see if sp[0]
     * tracks something predictable. Sentinel first, then reads with bit 7,
     * then read sp[0]. Print for each count.
     */
    ramsyscall_printf("=== n07_sp0_observation_after_count_reads ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    static const uint32_t counts[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256 };
    int n = sizeof(counts) / sizeof(counts[0]);

    for (int k = 0; k < n; k++) {
        sp[0] = 0xfeedf00du;
        dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0, counts[k], 16);
        dcache_dump_scratchpad(s_dump);
        ramsyscall_printf("  count=%3lu -> sp[0] = 0x%08lx\n",
                          counts[k], s_dump[0]);
    }

    sp[0] = 0;
)

CESTER_TEST(n08_sp0_with_address_offsets, dcache_tests,
    /* Vary the source address at fixed count=4. Does sp[0] reflect the
     * address somehow? */
    ramsyscall_printf("=== n08_sp0_with_address_offsets ===\n");
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;

    static const uint32_t bases[] = {
        TEST_DATA_KSEG0 + 0x000,
        TEST_DATA_KSEG0 + 0x004,
        TEST_DATA_KSEG0 + 0x010,
        TEST_DATA_KSEG0 + 0x080,
        TEST_DATA_KSEG0 + 0x100,
        TEST_DATA_KSEG0 + 0x200,
        TEST_DATA_KSEG0 + 0x300,
        TEST_DATA_KSEG0 + 0x3F0,
    };
    int n = sizeof(bases) / sizeof(bases[0]);

    for (int k = 0; k < n; k++) {
        sp[0] = 0xfeedf00du;
        dcache_run_reads_drained(BIU_DS_ONLY(0), bases[k], 4, 16);
        dcache_dump_scratchpad(s_dump);
        ramsyscall_printf("  base=0x%08lx -> sp[0] = 0x%08lx\n",
                          bases[k], s_dump[0]);
    }

    sp[0] = 0;
)

/* SECTION O / P (intentionally omitted from this binary): reads and writes
 * to the scratchpad address range (1F800XXX) in d-cache-only mode (RAM=0,
 * DS=1) deadlock the bus - a power cycle is required to recover. The
 * behavior is documented in psx-spx memorycontrol.md. If you want to
 * probe it, do so in a dedicated binary so a hang doesn't block the
 * rest of the suite. */

/* =========================================================================
 * SECTION Q. TAG / INV / LOCK bits combined with DS-only. These bits are
 * normally meaningful only with COP0 IsC=1. With IsC=0, do they affect
 * d-cache behavior at all?
 * ========================================================================= */

CESTER_TEST(q01_tag_bit_with_ds, dcache_tests,
    ramsyscall_printf("=== q01_tag_bit_with_ds ===\n");

    /* DS + TAG = bit 7 + bit 2 = 0x84 over base. */
    uint32_t biu = BIU_BASE | BIT_DS | (1u << 2);
    dcache_zero_scratchpad();
    dcache_run_reads_drained(biu, TEST_DATA_KSEG0, 16, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("ds+tag", s_dump);

    int matches = 0;
    for (uint32_t wi = 0; wi < 16; wi++) {
        if (s_dump[wi] == (BASE_PATTERN ^ wi)) matches++;
    }
    ramsyscall_printf("  16-word fills under DS+TAG: %d/16 matched\n", matches);
)

CESTER_TEST(q02_inv_bit_with_ds, dcache_tests,
    ramsyscall_printf("=== q02_inv_bit_with_ds ===\n");

    uint32_t biu = BIU_BASE | BIT_DS | (1u << 1);
    dcache_zero_scratchpad();
    dcache_run_reads_drained(biu, TEST_DATA_KSEG0, 16, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("ds+inv", s_dump);

    int matches = 0;
    for (uint32_t wi = 0; wi < 16; wi++) {
        if (s_dump[wi] == (BASE_PATTERN ^ wi)) matches++;
    }
    ramsyscall_printf("  16-word fills under DS+INV: %d/16 matched\n", matches);
)

CESTER_TEST(q03_lock_bit_with_ds, dcache_tests,
    ramsyscall_printf("=== q03_lock_bit_with_ds ===\n");

    uint32_t biu = BIU_BASE | BIT_DS | (1u << 0);
    dcache_zero_scratchpad();
    dcache_run_reads_drained(biu, TEST_DATA_KSEG0, 16, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("ds+lock", s_dump);

    int matches = 0;
    for (uint32_t wi = 0; wi < 16; wi++) {
        if (s_dump[wi] == (BASE_PATTERN ^ wi)) matches++;
    }
    ramsyscall_printf("  16-word fills under DS+LOCK: %d/16 matched\n", matches);
)

/* =========================================================================
 * SECTION R. Sub-word load granularity. lb / lh.
 * ========================================================================= */

CESTER_TEST(r01_byte_loads_dcache_mode, dcache_tests,
    ramsyscall_printf("=== r01_byte_loads_dcache_mode ===\n");

    dcache_zero_scratchpad();
    /* 16 byte-loads at consecutive byte addresses cover one cache line.
       Each lb reads 1 byte but the d-cache miss-fill might still be
       word-granular. */
    dcache_run_byte_reads(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 16);
    dcache_dump_scratchpad(s_dump);

    sp_signature("byte-reads", s_dump);
    sp_dump_nonzero("byte-reads", s_dump, 8);
)

CESTER_TEST(r02_half_loads_dcache_mode, dcache_tests,
    ramsyscall_printf("=== r02_half_loads_dcache_mode ===\n");

    dcache_zero_scratchpad();
    /* 16 halfword-loads at consecutive halfword addresses. */
    dcache_run_half_reads(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 16);
    dcache_dump_scratchpad(s_dump);

    sp_signature("half-reads", s_dump);
    sp_dump_nonzero("half-reads", s_dump, 8);
)

/* =========================================================================
 * SECTION S. DBLKSZ in normal scratchpad mode (RAM=1, DS=1). Earlier we
 * saw DBLKSZ inert in d-cache mode. Does it do anything at all?
 * ========================================================================= */

CESTER_TEST(s01_dblksz_in_normal_mode, dcache_tests,
    ramsyscall_printf("=== s01_dblksz_in_normal_mode ===\n");

    /* Pre-set sp pattern. Run reads with normal mode + various DBLKSZ.
       Verify scratchpad is undisturbed (nothing should fill it). */
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;
    for (int i = 0; i < 8; i++) sp[i] = 0x11000000u | (uint32_t)i;

    for (int dblksz = 0; dblksz < 4; dblksz++) {
        uint32_t biu = BIU_NORMAL | DBLKSZ(dblksz);
        dcache_run_reads_drained(biu, TEST_DATA_KSEG0, 16, 16);
        dcache_dump_scratchpad(s_dump);

        ramsyscall_printf("  dblk=%d normal+DBLKSZ: sp[0..3] = %08lx %08lx %08lx %08lx\n",
                          dblksz, s_dump[0], s_dump[1], s_dump[2], s_dump[3]);
    }

    for (int i = 0; i < 8; i++) sp[i] = 0;
)

/* =========================================================================
 * SECTION T. Same-cache-line reads. Do consecutive reads within a single
 * 16-byte cache line still produce one fill per read, or is there any
 * line-level behavior?
 * ========================================================================= */

CESTER_TEST(t01_within_line_reads, dcache_tests,
    ramsyscall_printf("=== t01_within_line_reads ===\n");

    /* Read 4 consecutive words at line 0 (0x80100000..0x8010000C). */
    dcache_zero_scratchpad();
    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 4, 16);
    dcache_dump_scratchpad(s_dump);
    sp_signature("4-words-1-line", s_dump);

    /* Re-read the same 4 words. With "every read is a miss", this should
       produce the same 4 fills again (no-op - same data). To prove they
       actually fired, modify sp[0] to a sentinel via volatile mid-test
       and re-read; it should be overwritten. */
    volatile uint32_t *sp = (volatile uint32_t *)SCRATCHPAD_BASE;
    sp[0] = 0xfeedf00du;
    sp[1] = 0xfeedf00du;
    sp[2] = 0xfeedf00du;
    sp[3] = 0xfeedf00du;

    dcache_run_reads_drained(BIU_DS_ONLY(0), TEST_DATA_KSEG0, 4, 16);
    dcache_dump_scratchpad(s_dump);
    ramsyscall_printf("  re-read after sentinel: sp[0..3] = %08lx %08lx %08lx %08lx\n",
                      s_dump[0], s_dump[1], s_dump[2], s_dump[3]);
    /* If reads always miss, sentinels were overwritten with pattern. */
)

CESTER_OPTIONS(
    CESTER_VERBOSE();
)
