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

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

CESTER_BODY(
    static int s_got40;
    static int s_got80;
    static uint32_t s_cause;
    static uint32_t s_epc;
    static uint32_t s_from;
    static uint32_t * s_resume;
    static uint32_t * s_regs;
    static void (*s_customhandler)() = NULL;
    uint32_t handler(uint32_t * regs, uint32_t from) {
        if (from == 0x40) s_got40 = 1;
        if (from == 0x80) s_got80 = 1;

        uint32_t cause;
        uint32_t epc;

        s_from = from;

        asm("mfc0 %0, $13\nnop\nmfc0 %1, $14\nnop" : "=r"(cause), "=r"(epc));

        s_cause = cause;
        s_epc = epc;

        if (s_customhandler) s_customhandler();

        return s_resume ? ((uint32_t)s_resume) : (epc + 4);
    }
    void installExceptionHandlers(uint32_t (*handler)(uint32_t * regs, uint32_t from));
    void uninstallExceptionHandlers();

    uint32_t branchbranch1();
    uint32_t branchbranch2();
    uint32_t jumpjump1();
    uint32_t jumpjump2();
    uint32_t cpu_LWR_LWL_half(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_nodelay(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_delayed(uint32_t buff[], uint32_t initial);
    uint32_t linkandload();
    uint32_t lwandlink();
    uint32_t nolink();

    uint32_t g_expectedEPC;

    static int s_interruptsWereEnabled;
)

CESTER_BEFORE_EACH(cpu_tests, testname, testindex,
    s_got40 = 0;
    s_got80 = 0;
    s_cause = 0;
    s_epc = 0;
    s_from = 0;
    s_resume = NULL;
    s_regs = NULL;
    s_customhandler = NULL;
    g_expectedEPC = 0;
)

CESTER_BEFORE_ALL(cpu_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    installExceptionHandlers(handler);
    syscall_flushCache();
)

CESTER_AFTER_ALL(cpu_tests,
    uninstallExceptionHandlers();
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

CESTER_TEST(cpu_quiet, cpu_tests,
    for (unsigned i = 0; i < 200000; i++) __asm__ volatile("");
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
)

CESTER_MAYBE_TEST(cpu_unaligned_write_fault, cpu_tests,
    uint32_t t;
    __asm__ volatile("la %0, 1f\nsw %0, g_expectedEPC\n1:\nsw $0, 1($0)" : "=r"(t));
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(1, s_got80);
    cester_assert_uint_eq(0x80, s_from);
    cester_assert_uint_eq(g_expectedEPC, s_epc);
)

CESTER_MAYBE_TEST(cpu_cop0_basic_write_bp, cpu_tests,
    uint32_t t;
    volatile uint32_t * ptr = (volatile uint32_t *) 0x58;
    *ptr = 1;
    __asm__ volatile(""
"    lui   %0, 0b1100101010000000\n"
"    mtc0  %0, $7\n"
"    li    %0, 0x58\n"
"    mtc0  %0, $5\n"
"    li    %0, 0xfffffff0\n"
"    mtc0  %0, $9\n" : "=r"(t));

    cester_assert_uint_eq(1, *ptr);

    __asm__ volatile("la %0, 1f\nsw %0, g_expectedEPC\n1:\nsw $0, 0x58($0)" : "=r"(t));

    __asm__ volatile("mtc0 $0, $7\n");

    cester_assert_uint_eq(0, *ptr);
    cester_assert_uint_eq(1, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0x40, s_from);
    cester_assert_uint_eq(g_expectedEPC, s_epc);
)

CESTER_MAYBE_TEST(cpu_cop0_unaligned_write_bp, cpu_tests,
    uint32_t t;
    volatile uint32_t * ptr = (volatile uint32_t *) 0x58;
    *ptr = 0x01020304;
    __asm__ volatile(""
"    lui   %0, 0b1100101010000000\n"
"    mtc0  %0, $7\n"
"    li    %0, 0x58\n"
"    mtc0  %0, $5\n"
"    li    %0, 0xfffffff0\n"
"    mtc0  %0, $9\n" : "=r"(t));

    cester_assert_uint_eq(0x01020304, *ptr);

    __asm__ volatile("la %0, 1f\nsw %0, g_expectedEPC\n1:\nsb $0, 0x59($0)" : "=r"(t));

    __asm__ volatile("mtc0 $0, $7\n");

    cester_assert_uint_eq(0x01020004, *ptr);
    cester_assert_uint_eq(1, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0x40, s_from);
    cester_assert_uint_eq(g_expectedEPC, s_epc);
)

CESTER_TEST(cpu_LWR_LWL_half, cpu_tests,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // when lwl is used alone, while waiting properly for the
    // delayed load, the register will be masked out
    uint32_t out = cpu_LWR_LWL_half(buff, 0xaabbccdd);
    cester_assert_uint_eq(0x88bbccdd, out);
)

CESTER_MAYBE_TEST(cpu_LWR_LWL_nodelay, cpu_tests,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // lwl and lwr are interlocked, so if you run both
    // right after another, on the same register, they
    // will cumulate delays, so not waiting the one-cycle
    // delay will still return the original, untouched value
    uint32_t out = cpu_LWR_LWL_nodelay(buff, 0xaabbccdd);
    cester_assert_uint_eq(0xaabbccdd, out);
)

CESTER_TEST(cpu_LWR_LWL_delayed, cpu_tests,
    uint32_t buff[2] = {0x11223344, 0x55667788};
    // this is the proper way of using lwl/lwr, waiting
    // one instruction to read the value of the register;
    // this test is here to ensure that there's no breakage
    // from the previous quirks fixes
    uint32_t out = cpu_LWR_LWL_delayed(buff, 0xaabbccdd);
    cester_assert_uint_eq(0x88112233, out);
)

CESTER_MAYBE_TEST(cpu_BRANCH_BRANCH_slot, cpu_tests,
    // running a branch in a branch delay slot is technically
    // not allowed, but some games still do this, and the
    // behavior is deterministic; read the assembly code
    // for the appropriate comments explaining how this works
    uint32_t out = branchbranch1();
    cester_assert_uint_eq(0x189, out);
    out = branchbranch2();
    cester_assert_uint_eq(9, out);
)

CESTER_MAYBE_TEST(cpu_JUMP_JUMP_slot, cpu_tests,
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
CESTER_TEST(cpu_DIV_by_zero, cpu_tests,
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

CESTER_TEST(cpu_DIVU_by_zero, cpu_tests,
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

CESTER_TEST(links, cpu_tests,
    uint32_t r = linkandload();
    cester_assert_uint_eq(0, r);
    r = lwandlink();
    cester_assert_uint_ne(0, r);
)

CESTER_TEST(nolink, cpu_tests,
    uint32_t r = nolink();
    cester_assert_uint_ne(0, r);
)
