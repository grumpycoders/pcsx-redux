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

CESTER_BEFORE_EACH(msan_invalid_tests, testname, testindex,
    mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
)

CESTER_AFTER_EACH(msan_invalid_tests, testname, testindex,
        pcsx_msanFree(mem_32_bit);
)

CESTER_BEFORE_ALL(msan_invalid_tests,
    pcsx_initMsan();
)

CESTER_AFTER_ALL(msan_invalid_tests,
    pcsx_resetMsan();
)

// clang-format on

CESTER_TEST(msan_32bit_sw_lw, msan_invalid_tests,
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

#define INVALID_SWX_LWX(name, sw_suffix, lw_suffix, store_off, load_off) \
    CESTER_TEST(name, msan_invalid_tests, \
        register uint32_t value = 0x11223344; \
        __asm__ __volatile__( \
            "sw" #sw_suffix " %0, " #store_off "(%1);" \
            : \
            : "r"(value), "r"(mem_32_bit) \
        ); \
        register volatile uint32_t result = 0xAABBCCDD; \
        __asm__ __volatile__( \
            "lw" #lw_suffix " %0, " #load_off "(%1);" \
            : "+r"(result) \
            : "r"(mem_32_bit) \
        ); \
        cester_assert_equal(result, 0xAABBCCDD); \
    )

// SWL => LWL
INVALID_SWX_LWX(msan_8bit_swl_16bit_lwl, l, l, 0, 1)
INVALID_SWX_LWX(msan_8bit_swl_24bit_lwl, l, l, 0, 2)
INVALID_SWX_LWX(msan_8bit_swl_32bit_lwl, l, l, 0, 3)

INVALID_SWX_LWX(msan_16bit_swl_24bit_lwl, l, l, 1, 2)
INVALID_SWX_LWX(msan_16bit_swl_32bit_lwl, l, l, 1, 3)

INVALID_SWX_LWX(msan_24bit_swl_32bit_lwl, l, l, 2, 3)

// SWL => LWR
INVALID_SWX_LWX(msan_8bit_swl_32bit_lwr, l, r, 0, 0)
INVALID_SWX_LWX(msan_8bit_swl_24bit_lwr, l, r, 0, 1)
INVALID_SWX_LWX(msan_8bit_swl_16bit_lwr, l, r, 0, 2)
INVALID_SWX_LWX(msan_8bit_swl_8bit_lwr, l, r, 0, 3)

INVALID_SWX_LWX(msan_16bit_swl_32bit_lwr, l, r, 1, 0)
INVALID_SWX_LWX(msan_16bit_swl_24bit_lwr, l, r, 1, 1)
INVALID_SWX_LWX(msan_16bit_swl_16bit_lwr, l, r, 1, 2)
INVALID_SWX_LWX(msan_16bit_swl_8bit_lwr, l, r, 1, 3)

INVALID_SWX_LWX(msan_24bit_swl_32bit_lwr, l, r, 2, 0)
INVALID_SWX_LWX(msan_24bit_swl_24bit_lwr, l, r, 2, 1)
INVALID_SWX_LWX(msan_24bit_swl_16bit_lwr, l, r, 2, 2)
INVALID_SWX_LWX(msan_24bit_swl_8bit_lwr, l, r, 2, 3)

// SWR => LWR
INVALID_SWX_LWX(msan_8bit_swr_32bit_lwr, r, r, 3, 0)
INVALID_SWX_LWX(msan_8bit_swr_24bit_lwr, r, r, 3, 1)
INVALID_SWX_LWX(msan_8bit_swr_16bit_lwr, r, r, 3, 2)

INVALID_SWX_LWX(msan_16bit_swr_32bit_lwr, r, r, 2, 0)
INVALID_SWX_LWX(msan_16bit_swr_24bit_lwr, r, r, 2, 1)

INVALID_SWX_LWX(msan_24bit_swr_32bit_lwr, r, r, 3, 0)

// SWR => LWL
INVALID_SWX_LWX(msan_8bit_swr_32bit_lwl, r, l, 3, 0)
INVALID_SWX_LWX(msan_8bit_swr_24bit_lwl, r, l, 3, 1)
INVALID_SWX_LWX(msan_8bit_swr_16bit_lwl, r, l, 3, 2)
INVALID_SWX_LWX(msan_8bit_swr_8bit_lwl, r, l, 3, 3)

INVALID_SWX_LWX(msan_16bit_swr_32bit_lwl, r, l, 2, 0)
INVALID_SWX_LWX(msan_16bit_swr_24bit_lwl, r, l, 2, 1)
INVALID_SWX_LWX(msan_16bit_swr_16bit_lwl, r, l, 2, 2)
INVALID_SWX_LWX(msan_16bit_swr_8bit_lwl, r, l, 2, 3)

INVALID_SWX_LWX(msan_24bit_swr_32bit_lwl, r, l, 1, 0)
INVALID_SWX_LWX(msan_24bit_swr_24bit_lwl, r, l, 1, 1)
INVALID_SWX_LWX(msan_24bit_swr_16bit_lwl, r, l, 1, 2)
INVALID_SWX_LWX(msan_24bit_swr_8bit_lwl, r, l, 1, 3)
