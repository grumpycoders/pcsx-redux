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

#include "crc32/crc32.h"

static uint32_t reverse(uint32_t value) {
    value = ((value >> 1) & 0x55555555) | ((value & 0x55555555) << 1);
    value = ((value >> 2) & 0x33333333) | ((value & 0x33333333) << 2);
    value = ((value >> 4) & 0x0f0f0f0f) | ((value & 0x0f0f0f0f) << 4);
    value = ((value >> 8) & 0x00ff00ff) | ((value & 0x00ff00ff) << 8);
    return (value >> 16) | (value << 16);
}

static void make_crc_table(uint32_t table[], const uint32_t poly_in, int reversed) {
    const uint32_t poly = reversed ? reverse(poly_in) : poly_in;
    for (unsigned d = 0; d < 256; d++) {
        uint32_t r = d;
        for (unsigned i = 0; i < 8; i++) {
            uint32_t flip = r & 1 ? poly : 0;
            r >>= 1;
            r ^= flip;
        }
        table[d] = r;
    }
}

static __attribute__((section(".scratchpad"))) uint32_t crc_table[256];

void init_crc32() { make_crc_table(crc_table, 0x04c11db7, 1); }

uint32_t process_crc32_unaligned(uint8_t *data, unsigned len, uint32_t crc) {
    while (len--) {
        crc = crc_table[(crc ^ *data++) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

uint32_t process_crc32_aligned(uint32_t *data, unsigned len, uint32_t crc) {
    while (len--) {
        uint32_t w = *data++;
        crc = crc_table[(crc ^ w) & 0xff] ^ (crc >> 8);
        w >>= 8;
        crc = crc_table[(crc ^ w) & 0xff] ^ (crc >> 8);
        w >>= 8;
        crc = crc_table[(crc ^ w) & 0xff] ^ (crc >> 8);
        w >>= 8;
        crc = crc_table[(crc ^ w) & 0xff] ^ (crc >> 8);
    }
    return crc;
}
