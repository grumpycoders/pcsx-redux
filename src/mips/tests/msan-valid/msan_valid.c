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

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

CESTER_BODY(
    static uint32_t* mem_32_bit = NULL;
)

CESTER_BEFORE_EACH(msan_valid_tests, testname, testindex,
    mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
)

CESTER_AFTER_EACH(msan_valid_tests, testname, testindex,
        pcsx_msanFree(mem_32_bit);
)

CESTER_BEFORE_ALL(msan_valid_tests,
    pcsx_initMsan();
)

CESTER_AFTER_ALL(msan_valid_tests,
    pcsx_resetMsan();
)

// clang-format on

CESTER_TEST(msan_32bit_sw_lw, msan_tests,
    register uint32_t value = 0x11223344;
    register volatile uint32_t result = 0;
    __asm__ __volatile__(
        "sw %1, 0(%2);"
        "lw %0, 0(%2);"
        : "=r"(result)
        : "r"(value), "r"(mem_32_bit)
    );
    cester_assert_equal(result, value);
)

#define LWX(load_suffix, offset, expected_result) \
    result = 0xAABBCCDD; \
    __asm__ __volatile__( \
        "lw" #load_suffix " %0, " #offset "(%1)" \
        : "+r"(result) \
        : "r"(mem_32_bit) \
    ); \
    cester_assert_equal(result, expected_result)

// SWL -> LWL

CESTER_TEST(msan_8bit_swl_8bit_lwl, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store upper byte 0x11
    __asm__ __volatile__(
        "swl %0, 0(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(l, 0, 0x11BBCCDD);
)

CESTER_TEST(msan_16bit_swl_8_to_16bit_lwl, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store upper 2 bytes 0x1122
    __asm__ __volatile__(
        "swl %0, 1(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(l, 0, 0x22BBCCDD);
    LWX(l, 1, 0x1122CCDD);
)

CESTER_TEST(msan_24bit_swl_8_to_24bit_lwl, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store upper 3 bytes 0x112233
    __asm__ __volatile__(
        "swl %0, 2(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(l, 0, 0x33BBCCDD);
    LWX(l, 1, 0x2233CCDD);
    LWX(l, 2, 0x112233DD);
)

CESTER_TEST(msan_32bit_swl_8_to_32bit_lwl, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store all 4 bytes 0x11223344
    __asm__ __volatile__(
        "swl %0, 3(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(l, 0, 0x44BBCCDD);
    LWX(l, 1, 0x3344CCDD);
    LWX(l, 2, 0x223344DD);
    LWX(l, 3, 0x11223344);
    LWX(, 0, 0x11223344);
)

// SWR -> LWR

CESTER_TEST(msan_8bit_swr_8bit_lwr, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store lower byte 0x44
    __asm__ __volatile__(
        "swr %0, 3(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(r, 3, 0xAABBCC44);
)

CESTER_TEST(msan_16bit_swr_8_to_16_bit_lwr, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store lower 2 bytes 0x3344
    __asm__ __volatile__(
        "swr %0, 2(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(r, 3, 0xAABBCC33);
    LWX(r, 2, 0xAABB4433);
)

CESTER_TEST(msan_24bit_swr_8_to_24_bit_lwr, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store lower 3 bytes 0x223344
    __asm__ __volatile__(
        "swr %0, 1(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(r, 3, 0xAABBCC22);
    LWX(r, 2, 0xAABB3322);
    LWX(r, 1, 0xAA443322);
)

CESTER_TEST(msan_32bit_swr_8_to_32_bit_lwr, msan_valid_tests,
    register uint32_t value = 0x11223344;
    // Store lower 3 bytes 0x11223344
    __asm__ __volatile__(
        "swr %0, 0(%1)"
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register volatile uint32_t result = 0xAABBCCDD;
    LWX(r, 3, 0xAABBCC11);
    LWX(r, 2, 0xAABB2211);
    LWX(r, 1, 0xAA332211);
    LWX(r, 0, 0x44332211);
    LWX(, 0, 0x44332211);
)

