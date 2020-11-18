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

#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"

CESTER_TEST(strcpy, test_instance,
    char b[32];
    char * s;

    b[16] = 'a';
    b[17] = 'b';
    b[18] = 'c';
    b[19] = 0;

    s = syscall_strcpy(b, b + 16);
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal(b, b + 16);
)

CESTER_TEST(memset, test_instance,
    char b[9];
    char * s;

    b[8] = 0;
    s = syscall_memset(b, 's', sizeof(b) - 1);
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal("ssssssss", b);
)

CESTER_TEST(strncpyBigger, test_instance,
    char b[8];
    char * s;

    syscall_memset(b, 0, sizeof(b));
    s = syscall_strncpy(b, "0123456789abcdef", sizeof(b) - 1);
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal("0123456", b);
)

CESTER_TEST(strncpySmaller, test_instance,
    char b[8] = { 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'};
    char * s;

    s = syscall_strncpy(b, "abc", sizeof(b));
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal("abc", b);
    cester_assert_int_eq('a', b[0]);
    cester_assert_int_eq('b', b[1]);
    cester_assert_int_eq('c', b[2]);
    cester_assert_int_eq(0, b[3]);
    cester_assert_int_eq(0, b[4]);
    cester_assert_int_eq(0, b[5]);
    cester_assert_int_eq(0, b[6]);
    cester_assert_int_eq(0, b[7]);
)

CESTER_TEST(strncatBigger, test_instance,
    char b[8] = { 'a', 'b', 'c', 0, 'x', 'x', 'x', 'x' };
    char * s;

    s = syscall_strncat(b, "123456", 3);
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal("abc123", b);
    cester_assert_int_eq(0, b[6]);
    cester_assert_int_eq('x', b[7]);
)

CESTER_TEST(strncatSmaller, test_instance,
    char b[8] = { 'a', 'b', 'c', 0, 'x', 'x', 'x', 'x' };
    char * s;

    s = syscall_strncat(b, "123", 6);
    cester_assert_ptr_equal(b, s);
    cester_assert_str_equal("abc123", b);
    cester_assert_int_eq(0, b[6]);
    cester_assert_int_eq('x', b[7]);
)
