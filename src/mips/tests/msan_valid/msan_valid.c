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

#include "mips/common/hardware/pcsxhw.h"
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
#include "common/hardware/psxhw.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

CESTER_BEFORE_ALL(msan_valid_tests,
    pcsx_initMsan();
)

CESTER_AFTER_ALL(msan_valid_tests,
    pcsx_resetMsan();
)

// clang-format on

CESTER_TEST(msan_32bit_sw_lw, msan_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    register uint32_t result = 0;
    __asm__ __volatile__(
        "sw %1, 0(%2)",
        "lw %0, 0(%2)"
        : "=r"(result)
        : "r"(value), "r"(mem_32_bit)
    );
    pcsx_msanFree(mem_32_bit);
    EXPECT_EQ(result, value);
)

// SWL -> LWL

CESTER_TEST(msan_8bit_swl_8bit_lwl, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store upper byte 0x11
    __asm__ __volatile__(
        "swl %0, 0(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x11BBCCDD);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_16bit_swl_8_to_16bit_lwl, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store upper 2 bytes 0x1122
    __asm__ __volatile__(
        "swl %0, 1(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x22BBCCDD);
    result = 0
    __asm__ __volatile__(
        "lwl %0 1(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x1122CCDD);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_24bit_swl_8_to_24bit_lwl, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store upper 3 bytes 0x112233
    __asm__ __volatile__(
        "swl %0, 2(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x33BBCCDD);
    result = 0
    __asm__ __volatile__(
        "lwl %0 1(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x2233CCDD);
    result = 0
    __asm__ __volatile__(
        "lwl %0 2(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x112233DD);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_swl_8_to_lwl, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store all 4 bytes 0x11223344
    __asm__ __volatile__(
        "swl %0, 3(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x44BBCCDD);
    result = 0xAABBCCDD; 
    __asm__ __volatile__(
        "lwl %0 1(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x3344CCDD);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 2(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x223344DD);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 3(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x11223344);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lw %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x11223344);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

// SWR -> LWR

CESTER_TEST(msan_8bit_swr_8bit_lwr, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store lower byte 0x44
    __asm__ __volatile__(
        "swr %0, 3(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 3(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABBCC44);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_8bit_swr_8_to_16_bit_lwr, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store lower 2 bytes 0x3344
    __asm__ __volatile__(
        "swr %0, 2(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 3(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABBCC44);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 2(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABB3344);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_8bit_swr_8_to_24_bit_lwr, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store lower 3 bytes 0x223344
    __asm__ __volatile__(
        "swr %0, 1(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 3(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABBCC44);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 2(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABB3344);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 1(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAA223344);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

CESTER_TEST(msan_8bit_swr_8_to_32_bit_lwr, msan_valid_tests
    register uint32_t mem_32_bit = (uint32_t*) pcsx_msanAlloc(sizeof(uint32_t));
    register uint32_t value = 0x11223344
    // Store lower 3 bytes 0x11223344
    __asm__ __volatile__(
        "swr %0, 0(%1)",
        :
        : "r"(value), "r"(mem_32_bit)
    );
    register uint32_t result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 3(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABBCC44);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 2(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAABB3344);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 1(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0xAA223344);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lwl %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x11223344);
    result = 0xAABBCCDD;
    __asm__ __volatile__(
        "lw %0 0(%1)",
        : "=r"(result)
        : "r"(mem_32_bit)
    );
    ASSERT_EQ(result, 0x11223344);
    pcsx_msanFree(mem_32_bit);
    SUCCESS();
)

