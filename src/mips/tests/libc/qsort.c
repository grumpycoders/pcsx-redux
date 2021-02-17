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

// clang-format off

CESTER_BODY(
    static int icmp(const void * a, const void * b) {
        return *(const int *) a - *(const int *) b;
    }
)

CESTER_TEST(qsortWithNumbers, test_instance,
    static const int sorted[] = {
        127,
        257,
        509,
        1021,
        2053,
        4099,
        8191,
        16381,
        32771,
        65537,
        131071,
        262147,
        524287,
        1048573,
        2097143,
        4194301,
    };
    int input[] = {
        2097143,
        8191,
        509,
        1021,
        257,
        65537,
        4099,
        1048573,
        524287,
        127,
        131071,
        4194301,
        16381,
        32771,
        2053,
        262147,
    };

    static const int size = sizeof(input) / sizeof(input[0]);

    syscall_qsort(input, size, sizeof(input[0]), icmp);

    for (int i = 0; i < size; i++) {
        cester_assert_int_eq(sorted[i], input[i]);
    }
)

CESTER_BODY(
    static int scmp(const void * a, const void * b) {
        return syscall_strcmp(*(const char **) a, *(const char **) b);
    }
)

CESTER_TEST(qsortWithStrings, test_instance,
    static const char * const sorted[] = {
        "arch",
        "authority",
        "calculating",
        "duck",
        "dysfunctional",
        "embarrassed",
        "fish",
        "flow",
        "hanging",
        "help",
        "helpful",
        "linen",
        "materialistic",
        "outstanding",
        "parched",
        "purple",
        "remain",
        "robin",
        "skilly",
        "spiteful",
        "stove",
        "undesirable",
        "wry",
    };
    const char * input[] = {
        "stove",
        "calculating",
        "duck",
        "undesirable",
        "skilly",
        "robin",
        "linen",
        "help",
        "materialistic",
        "parched",
        "hanging",
        "outstanding",
        "spiteful",
        "remain",
        "authority",
        "helpful",
        "wry",
        "purple",
        "fish",
        "embarrassed",
        "arch",
        "flow",
        "dysfunctional",
    };

    static const int size = sizeof(input) / sizeof(input[0]);

    syscall_qsort(input, size, sizeof(input[0]), scmp);

    for (int i = 0; i < size; i++) {
        cester_assert_str_equal(sorted[i], input[i]);
    }
)
