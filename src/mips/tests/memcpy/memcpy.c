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

/* This is to test regressions on the fast memcpy code located in common/crt0/memory.s */

CESTER_BODY(
    void* __wrap_memcpy(void* dest, const void* src, size_t n);
)

CESTER_TEST(fastmemcpySmall, test_instance,
    char in[4] = { 1, 2, 3, 4 };
    char out[4] = { 0, 0, 0, 0 };
    void* result = __wrap_memcpy(out, in, 3);
    cester_assert_ptr_equal(result, out);
    cester_assert_uint_eq(out[0], in[0]);
    cester_assert_uint_eq(out[1], in[1]);
    cester_assert_uint_eq(out[2], in[2]);
    cester_assert_uint_eq(out[3], 0);
)

CESTER_TEST(fastmemcpyLarger, test_instance,
    char in[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    char out[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    void* result = __wrap_memcpy(out, in, sizeof(in));
    cester_assert_ptr_equal(result, out);
    cester_assert_uint_eq(out[0], in[0]);
    cester_assert_uint_eq(out[1], in[1]);
    cester_assert_uint_eq(out[2], in[2]);
    cester_assert_uint_eq(out[3], in[3]);
    cester_assert_uint_eq(out[4], in[4]);
    cester_assert_uint_eq(out[5], in[5]);
    cester_assert_uint_eq(out[6], in[6]);
    cester_assert_uint_eq(out[7], in[7]);
    cester_assert_uint_eq(out[8], in[8]);
    cester_assert_uint_eq(out[9], in[9]);
    cester_assert_uint_eq(out[10], in[10]);
)

CESTER_TEST(fastmemcpyLargest, test_instance,
    char in[50];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 50; i++) {
        in[i] = i;
    }
    void* result = __wrap_memcpy(out, in, sizeof(in));
    cester_assert_ptr_equal(result, out);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i], i);
    }
)

CESTER_TEST(fastmemcpyDestUnaligned, test_instance,
    char in[50];
    char out[51] = { 0 };
    for (unsigned i = 0; i < 50; i++) {
        in[i] = i;
    }
    void* result = __wrap_memcpy(out + 1, in, sizeof(in));
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i + 1], i);
    }
)

CESTER_TEST(fastmemcpySrcUnaligned, test_instance,
    char in[51];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __wrap_memcpy(out, in + 1, sizeof(out));
    cester_assert_ptr_equal(result, out);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i], i + 1);
    }
)

CESTER_TEST(fastmemcpyBothLikeUnaligned, test_instance,
    char in[51];
    char out[51] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __wrap_memcpy(out + 1, in + 1, 50);
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i + 1], i + 1);
    }
)

CESTER_TEST(fastmemcpyBothUnlikeUnaligned, test_instance,
    char in[51];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __wrap_memcpy(out + 1, in + 2, 49);
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 49; i++) {
        cester_assert_equal(out[i + 1], i + 2);
    }
)

CESTER_TEST(memcpySmall, test_instance,
    char in[4] = { 1, 2, 3, 4 };
    char out[4] = { 0, 0, 0, 0 };
    void* result = __builtin_memcpy(out, in, 3);
    cester_assert_ptr_equal(result, out);
    cester_assert_uint_eq(out[0], in[0]);
    cester_assert_uint_eq(out[1], in[1]);
    cester_assert_uint_eq(out[2], in[2]);
    cester_assert_uint_eq(out[3], 0);
)

CESTER_TEST(memcpyLarger, test_instance,
    char in[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    char out[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    void* result = __builtin_memcpy(out, in, sizeof(in));
    cester_assert_ptr_equal(result, out);
    cester_assert_uint_eq(out[0], in[0]);
    cester_assert_uint_eq(out[1], in[1]);
    cester_assert_uint_eq(out[2], in[2]);
    cester_assert_uint_eq(out[3], in[3]);
    cester_assert_uint_eq(out[4], in[4]);
    cester_assert_uint_eq(out[5], in[5]);
    cester_assert_uint_eq(out[6], in[6]);
    cester_assert_uint_eq(out[7], in[7]);
    cester_assert_uint_eq(out[8], in[8]);
    cester_assert_uint_eq(out[9], in[9]);
    cester_assert_uint_eq(out[10], in[10]);
)

CESTER_TEST(memcpyLargest, test_instance,
    char in[50];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 50; i++) {
        in[i] = i;
    }
    void* result = __builtin_memcpy(out, in, sizeof(in));
    cester_assert_ptr_equal(result, out);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i], i);
    }
)

CESTER_TEST(memcpyDestUnaligned, test_instance,
    char in[50];
    char out[51] = { 0 };
    for (unsigned i = 0; i < 50; i++) {
        in[i] = i;
    }
    void* result = __builtin_memcpy(out + 1, in, sizeof(in));
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i + 1], i);
    }
)

CESTER_TEST(memcpySrcUnaligned, test_instance,
    char in[51];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __builtin_memcpy(out, in + 1, sizeof(out));
    cester_assert_ptr_equal(result, out);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i], i + 1);
    }
)

CESTER_TEST(memcpyBothLikeUnaligned, test_instance,
    char in[51];
    char out[51] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __builtin_memcpy(out + 1, in + 1, 50);
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 50; i++) {
        cester_assert_equal(out[i + 1], i + 1);
    }
)

CESTER_TEST(memcpyBothUnlikeUnaligned, test_instance,
    char in[51];
    char out[50] = { 0 };
    for (unsigned i = 0; i < 51; i++) {
        in[i] = i;
    }
    void* result = __builtin_memcpy(out + 1, in + 2, 49);
    cester_assert_ptr_equal(result, out + 1);
    cester_assert_equal(out[0], 0);
    for (unsigned i = 0; i < 49; i++) {
        cester_assert_equal(out[i + 1], i + 2);
    }
)
