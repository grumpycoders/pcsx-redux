/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

/* Sweep bounds: SWEEP_MAX spans several 32-byte blocks past the point where the
   block loop engages; SWEEP_SLACK is the guard region checked for overrun. */
#define SWEEP_MAX 200
#define SWEEP_SLACK 8

/* This is to test regressions on the fast memset code located in common/crt0/memory-s.s */

CESTER_BODY(
    void* __wrap_memset(void* dest, int c, size_t n);
)

CESTER_TEST(fastmemsetSmall, test_instance,
    char buf[] = { 0, 0, 0, 0 };
    void * result = __wrap_memset(buf, 0x55, 3);
    for (unsigned i = 0; i < 3; i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_uint_eq(buf[3], 0);
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(fastmemsetLarger, test_instance,
    char buf[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    void * result = __wrap_memset(buf, 0x55, 11);
    for (unsigned i = 0; i < 11; i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_uint_eq(buf[11], 0);
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(fastmemsetLargest, test_instance,
    char buf[1000] = { 0 };
    void * result = __wrap_memset(buf, 0x55, sizeof(buf));
    for (unsigned i = 0; i < sizeof(buf); i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(fastmemsetUnaligned, test_instance,
    char buf[1000] = { 0 };
    void * result = __wrap_memset(buf + 1, 0x55, sizeof(buf) - 1);
    cester_assert_uint_eq(buf[0], 0);
    for (unsigned i = 1; i < sizeof(buf); i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_ptr_equal(result, buf + 1);
)

CESTER_TEST(memsetSmall, test_instance,
    char buf[] = { 0, 0, 0, 0 };
    void * result = __builtin_memset(buf, 0x55, 3);
    for (unsigned i = 0; i < 3; i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_uint_eq(buf[3], 0);
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(memsetLarger, test_instance,
    char buf[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    void * result = __builtin_memset(buf, 0x55, 11);
    for (unsigned i = 0; i < 11; i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_uint_eq(buf[11], 0);
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(memsetLargest, test_instance,
    char buf[1000] = { 0 };
    void * result = __builtin_memset(buf, 0x55, sizeof(buf));
    for (unsigned i = 0; i < sizeof(buf); i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_ptr_equal(result, buf);
)

CESTER_TEST(memsetUnaligned, test_instance,
    char buf[1000] = { 0 };
    void * result = __builtin_memset(buf + 1, 0x55, sizeof(buf) - 1);
    cester_assert_uint_eq(buf[0], 0);
    for (unsigned i = 1; i < sizeof(buf); i++) {
        cester_assert_uint_eq(buf[i], 0x55);
    }
    cester_assert_ptr_equal(result, buf + 1);
)

/* Length SWEEP, not length samples. The cases above pick hand-chosen awkward
   lengths, and an awkward length is precisely one that misses a block boundary
   - which is where a hand-unrolled loop's bugs live. Sweep every alignment
   across several block sizes instead, with guard bytes on the far side so an
   overrun fails as loudly as a shortfall. */

CESTER_BODY(
    static unsigned char s_sweepDst[SWEEP_MAX + SWEEP_SLACK];
    static unsigned char s_sweepRef[SWEEP_MAX + SWEEP_SLACK];

    /* 0 on success, otherwise 1 + the index of the first byte that disagreed,
       so a failure names a place rather than just tripping a boolean. */
    static unsigned sweepMemsetOnce(unsigned align, unsigned n) {
        for (unsigned i = 0; i < SWEEP_MAX + SWEEP_SLACK; i++) {
            s_sweepDst[i] = 0xa5;
            s_sweepRef[i] = 0xa5;
        }
        for (unsigned i = 0; i < n; i++) s_sweepRef[align + i] = 0x5a;
        void *r = __wrap_memset(s_sweepDst + align, 0x5a, n);
        if (r != s_sweepDst + align) return 1;
        for (unsigned i = 0; i < SWEEP_MAX + SWEEP_SLACK; i++) {
            if (s_sweepDst[i] != s_sweepRef[i]) return i + 1;
        }
        return 0;
    }
)

/* Every destination alignment, every length up to several block sizes, with
   guard bytes on the far side so an overrun fails as loudly as a shortfall. */
CESTER_TEST(fastmemsetSweep, test_instance,
    unsigned failures = 0, firstAlign = 0, firstN = 0, firstAt = 0;
    for (unsigned align = 0; align < 4; align++) {
        for (unsigned n = 0; n <= SWEEP_MAX; n++) {
            unsigned bad = sweepMemsetOnce(align, n);
            if (bad) {
                if (!failures) { firstAlign = align; firstN = n; firstAt = bad - 1; }
                failures++;
            }
        }
    }
    if (failures) {
        ramsyscall_printf("  memset sweep: %u failing cases, first align=%u n=%u at byte %u\n",
                          failures, firstAlign, firstN, firstAt);
    }
    cester_assert_uint_eq(0, failures);
)
