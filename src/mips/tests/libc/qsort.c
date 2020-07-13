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

CESTER_BODY(
    static int icmp(const void * a, const void * b) {
        return *(const int*)a - *(const int*)b;
    }
)

CESTER_TEST(numbers, qsort,
    static const int sorted[] = {
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
        8388617,
        16777213,
        33554467,
        67108859,
        134217757,
        268435459,
        536870909,
        1073741827,
    };
    int input[] = {
        2097143,
        8191,
        509,
        1021,
        67108859,
        65537,
        4099,
        134217757,
        1073741827,
        1048573,
        524287,
        131071,
        16777213,
        4194301,
        536870909,
        8388617,
        16381,
        32771,
        2053,
        268435459,
        33554467,
        262147,
    };

    static const int size = sizeof(input) / sizeof(input[0]);

    syscall_qsort(input, size, sizeof(input[0]), icmp);

    for (int i = 0; i < size; i++) {
        cester_assert_int_eq(input[i], sorted[i]);
    }
)
