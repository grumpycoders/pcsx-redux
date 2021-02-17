/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "openbios/patches/hash.h"

static const uint32_t hash_prime = 0xb503198f;

static inline uint32_t hashone(uint32_t a) {
    a = (a ^ 61) ^ (a >> 16);
    a += (a << 3);
    a ^= (a >> 4);
    a *= 0x27d4eb2f;
    a ^= (a >> 15);
    return a;
}

uint32_t patch_hash(const uint32_t* ptr, uint8_t* maskPtr, unsigned len) {
    uint32_t hash = 0x5810d659;
    uint32_t mask = 1;

    while (len--) {
        uint32_t n = *ptr++;
        if (mask == 1) mask = *maskPtr++ | 0x100;
        switch (mask & 3) {
            case 1:
                n &= 0xffff0000;
                break;
            case 2:
                n &= 0xfc000000;
                break;
            case 3:
                n = 0;
                break;
        }
        mask >>= 2;

        hash += hashone(n);
        hash *= hash_prime;
    }

    return hash;
}
