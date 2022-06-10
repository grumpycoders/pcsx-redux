/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include "cester-cop0.c"

CESTER_TEST(cpu_cop0_basic_write_bp, cpu_tests,
    uint32_t expectedEPC;
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

    __asm__ volatile("la %0, 1f\n1:\nsw $0, 0x58($0)" : "=r"(expectedEPC));

    __asm__ volatile("mtc0 $0, $7\n");

    cester_assert_uint_eq(0, *ptr);
    cester_assert_uint_eq(1, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0x40, s_from);
    cester_assert_uint_eq(expectedEPC, s_epc);
)

CESTER_TEST(cpu_cop0_unaligned_write_bp, cpu_tests,
    uint32_t expectedEPC;
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

    __asm__ volatile("la %0, 1f\n1:\nsb $0, 0x59($0)" : "=r"(expectedEPC));

    __asm__ volatile("mtc0 $0, $7\n");

    cester_assert_uint_eq(0x01020004, *ptr);
    cester_assert_uint_eq(1, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0x40, s_from);
    cester_assert_uint_eq(expectedEPC, s_epc);
)
