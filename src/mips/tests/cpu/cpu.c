/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

CESTER_BODY(
    uint32_t branchbranch1();
    uint32_t branchbranch2();
    uint32_t jumpjump1();
    uint32_t jumpjump2();
    uint32_t cpu_LWR_LWL_half(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_nodelay(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_delayed(uint32_t buff[], uint32_t initial);
)

CESTER_TEST(cpu_LWR_LWL_half, test_instance,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // when lwl is used alone, while waiting properly for the
    // delayed load, the register will be masked out
    uint32_t out = cpu_LWR_LWL_half(buff, 0xaabbccdd);
    cester_assert_uint_eq(0x88bbccdd, out);
)

CESTER_TEST(cpu_LWR_LWL_nodelay, test_instance,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // lwl and lwr are interlocked, so if you run both
    // right after another, on the same register, they
    // will cumulate delays, so not waiting the one-cycle
    // delay will still return the original, untouched value
    uint32_t out = cpu_LWR_LWL_nodelay(buff, 0xaabbccdd);
    cester_assert_uint_eq(0xaabbccdd, out);
)

CESTER_TEST(cpu_LWR_LWL_delayed, test_instance,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // this is the proper way of using lwl/lwr, waiting
    // one instruction to read the value of the register;
    // this test is here to ensure that there's no breakage
    // from the previous quirks fixes
    uint32_t out = cpu_LWR_LWL_delayed(buff, 0xaabbccdd);
    cester_assert_uint_eq(0x88112233, out);
)

CESTER_SKIP_TEST(cpu_BRANCH_BRANCH_slot, test_instance,
    // running a branch in a branch delay slot is technically
    // not allowed, but some games still do this, and the
    // behavior is deterministic; read the assembly code
    // for the appropriate comments explaining how this works
    uint32_t out = branchbranch1();
    cester_assert_uint_eq(0x189, out);
    out = branchbranch2();
    cester_assert_uint_eq(9, out);
)

CESTER_SKIP_TEST(cpu_JUMP_JUMP_slot, test_instance,
    // while branches are relative PC adjustments, jumps
    // are absolute; this is technically the same test as
    // above, but without the relative quirkness
    uint32_t out = jumpjump1();
    cester_assert_uint_eq(0x69, out);
    out = jumpjump2();
    cester_assert_uint_eq(21, out);
)

// the CPU allows for division by zero, and when
// doing so, the hi register will contain the dividend,
// while the lo register will contain -1; some games
// rely on this behavior to work properly
CESTER_TEST(cpu_DIV_by_zero, test_instance,
    int32_t hi, lo;
    __asm__ __volatile__(
        "li    $v0, 0x55555555\n"
        "mthi  $v0\n"
        "mtlo  $v0\n"
        "nop\n"
        "div   $0, $0\n"
        "mfhi  %0\n"
        "mflo  %1\n"
        "nop\n"
        : "=r"(hi), "=r"(lo) : : "v0"
    );

    cester_assert_int_eq(0, hi);
    cester_assert_int_eq(-1, lo);

    __asm__ __volatile__(
        "li    $v0, 0x55555555\n"
        "mthi  $v0\n"
        "mtlo  $v0\n"
        "li    $v0, 42\n"
        ".word 0x0040001a\n" // any attempt at doing a div here will result
                             // in the compiler being too smart for its own good
        "mfhi  %0\n"
        "mflo  %1\n"
        "nop\n"
        : "=r"(hi), "=r"(lo) : : "v0"
    );

    cester_assert_int_eq(42, hi);
    cester_assert_int_eq(-1, lo);
)

CESTER_TEST(cpu_DIVU_by_zero, test_instance,
    int32_t hi, lo;
    __asm__ __volatile__(
        "li    $v0, 0x55555555\n"
        "mthi  $v0\n"
        "mtlo  $v0\n"
        "nop\n"
        "divu  $0, $0\n"
        "mfhi  %0\n"
        "mflo  %1\n"
        "nop\n"
        : "=r"(hi), "=r"(lo) : : "v0"
    );

    cester_assert_int_eq(0, hi);
    cester_assert_int_eq(-1, lo);

    __asm__ __volatile__(
        "li    $v0, 0x55555555\n"
        "mthi  $v0\n"
        "mtlo  $v0\n"
        "li    $v0, 42\n"
        ".word 0x0040001b\n" // any attempt at doing a divu here will result
                             // in the compiler being too smart for its own good
        "mfhi  %0\n"
        "mflo  %1\n"
        "nop\n"
        : "=r"(hi), "=r"(lo) : : "v0"
    );

    cester_assert_int_eq(42, hi);
    cester_assert_int_eq(-1, lo);
)
