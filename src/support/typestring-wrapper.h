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

#pragma once

#include "typestring.hh"

#if defined(_MSC_VER) && !defined(__clang__)
#define TYPESTRING_MAX_CONST_CHAR 63

#define TYPESTRING_MIN(a, b) (a) < (b) ? (a) : (b)

#define TYPESTRING(s)                                                                                               \
    irqus::typestring<                                                                                              \
        ts_getChr(s, 0), ts_getChr(s, 1), ts_getChr(s, 2), ts_getChr(s, 3), ts_getChr(s, 4), ts_getChr(s, 5),       \
        ts_getChr(s, 6), ts_getChr(s, 7), ts_getChr(s, 8), ts_getChr(s, 9), ts_getChr(s, 10), ts_getChr(s, 11),     \
        ts_getChr(s, 12), ts_getChr(s, 13), ts_getChr(s, 14), ts_getChr(s, 15), ts_getChr(s, 16), ts_getChr(s, 17), \
        ts_getChr(s, 18), ts_getChr(s, 19), ts_getChr(s, 20), ts_getChr(s, 21), ts_getChr(s, 22), ts_getChr(s, 23), \
        ts_getChr(s, 24), ts_getChr(s, 25), ts_getChr(s, 26), ts_getChr(s, 27), ts_getChr(s, 28), ts_getChr(s, 29), \
        ts_getChr(s, 30), ts_getChr(s, 31), ts_getChr(s, 32), ts_getChr(s, 33), ts_getChr(s, 34), ts_getChr(s, 35), \
        ts_getChr(s, 36), ts_getChr(s, 37), ts_getChr(s, 38), ts_getChr(s, 39), ts_getChr(s, 40), ts_getChr(s, 41), \
        ts_getChr(s, 42), ts_getChr(s, 43), ts_getChr(s, 44), ts_getChr(s, 45), ts_getChr(s, 46), ts_getChr(s, 47), \
        ts_getChr(s, 48), ts_getChr(s, 49), ts_getChr(s, 50), ts_getChr(s, 51), ts_getChr(s, 52), ts_getChr(s, 53), \
        ts_getChr(s, 54), ts_getChr(s, 55), ts_getChr(s, 56), ts_getChr(s, 57), ts_getChr(s, 58), ts_getChr(s, 59), \
        ts_getChr(s, 60), ts_getChr(s, 61), ts_getChr(s, 62), ts_getChr(s, 63)>

#define ts_getChr(name, ii) \
    ((TYPESTRING_MIN(ii, TYPESTRING_MAX_CONST_CHAR)) < sizeof(name) / sizeof(*name) ? name[ii] : 0)

#else
#define TYPESTRING(s) typestring_is(s)
#endif
