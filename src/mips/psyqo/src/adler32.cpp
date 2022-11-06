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

#include "psyqo/adler32.hh"

#include <EASTL/algorithm.h>

static constexpr uint32_t MOD_ADLER = 65521;

uint32_t psyqo::adler32(uint8_t* buffer, unsigned length, uint32_t sum) {
    if (length < 8) return adler32_bytes(buffer, length, sum);
    uint32_t align = reinterpret_cast<uintptr_t>(buffer) & 3;
    if (align) {
        align = 4 - align;
        sum = adler32_bytes(buffer, align, sum);
        buffer += align;
        length -= align;
    }
    unsigned words = length >> 2;
    sum = adler32_words(reinterpret_cast<uint32_t*>(buffer), words, sum);
    return adler32_bytes(buffer + (words << 2), length & 3, sum);
}

uint32_t psyqo::adler32_bytes(uint8_t* buffer, unsigned length, uint32_t sum) {
    uint32_t a = sum & 0xffff;
    uint32_t b = sum >> 16;
    unsigned i = 0;
    while (i < length) {
        unsigned block = eastl::min(length - i, 3800u) + i;
        while (i < block) {
            a += buffer[i++];
            b += a;
        }
        a = 15 * (a >> 16) + (a & 0xffff);
        b = 15 * (b >> 16) + (b & 0xffff);
    }
    a %= MOD_ADLER;
    b %= MOD_ADLER;
    return (b << 16) | a;
}

uint32_t psyqo::adler32_words(uint32_t* buffer, unsigned length, uint32_t sum) {
    uint32_t a = sum & 0xffff;
    uint32_t b = sum >> 16;
    unsigned i = 0;
    while (i < length) {
        unsigned block = eastl::min(length - i, 950u) + i;
        while (i < block) {
            uint32_t word = buffer[i++];
            a += word & 0xff;
            b += a;
            word >>= 8;
            a += word & 0xff;
            b += a;
            word >>= 8;
            a += word & 0xff;
            b += a;
            word >>= 8;
            a += word & 0xff;
            b += a;
        }
        a = 15 * (a >> 16) + (a & 0xffff);
        b = 15 * (b >> 16) + (b & 0xffff);
    }
    a %= MOD_ADLER;
    b %= MOD_ADLER;
    return (b << 16) | a;
}
