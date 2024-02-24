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

#include <stddef.h>
#include <stdint.h>

// These are the 4 essential functions expected by gcc for a naked build.
// The implementation of memcpy is in memory-s.s, and the rest are here.
// The weak attribute is used to allow the user to override these functions
// with their own implementation if they so desire. The memory-s.s implementation
// is a simple byte copy, and is not optimized for speed. The file also contains
// a faster but bigger implementation that can be used instead, called
// __wrap_memcpy. The user can override memcpy with __wrap_memcpy to use it using
// the -Wl,--wrap=memcpy switch to the linker using LDFLAGS. The same file also
// contains a fast implementation of memset, called __wrap_memset, that can be
// used in the same way.

void* memcpy(void* s1_, const void* s2_, size_t n);

__attribute__((weak)) void* memmove(void* s1_, const void* s2_, size_t n) {
    uint8_t* s1 = (uint8_t*)s1_;
    const uint8_t* s2 = (uint8_t*)s2_;
    size_t i;

    uint8_t* e1 = s1 + n;
    const uint8_t* e2 = s2 + n;

    if ((s1 <= s2) && (s2 <= e1) || ((s2 <= s1) && (s1 <= e2))) {
        if (s1 < s2) {
            for (i = 0; i < n; i++) *s1++ = *s2++;
        } else if (s1 > s2) {
            s1 += n;
            s2 += n;
            for (i = 0; i < n; i++) *--s1 = *--s2;
        }
    } else {
        return memcpy(s1_, s2_, n);
    }

    return s1_;
}

__attribute__((weak)) int memcmp(const void* s1_, const void* s2_, size_t n) {
    uint8_t* s1 = (uint8_t*)s1_;
    const uint8_t* s2 = (uint8_t*)s2_;
    size_t i;

    for (i = 0; i < n; i++, s1++, s2++) {
        if (*s1 < *s2) {
            return -1;
        } else if (*s1 > *s2) {
            return 1;
        }
    }

    return 0;
}

__attribute__((weak)) void* memset(void* s_, int c, size_t n) {
    uint8_t* s = (uint8_t*)s_;
    size_t i;

    for (i = 0; i < n; i++) *s++ = (uint8_t)c;

    return s_;
}
