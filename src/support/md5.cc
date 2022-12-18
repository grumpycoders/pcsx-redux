/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "support/md5.h"

#include <cstring>

PCSX::MD5::MD5() {
    m_state[0] = 0x67452301;
    m_state[1] = 0xefcdab89;
    m_state[2] = 0x98badcfe;
    m_state[3] = 0x10325476;
}

void PCSX::MD5::update(const void* data_, uint64_t length) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(data_);
    unsigned fill = m_length & 0x3f;

    if (!length) return;

    m_length += length;

    if (fill && ((length + fill) >= 64)) {
        unsigned stub = 64 - fill;
        std::memcpy(m_buffer + fill, data, stub);
        process(m_buffer);
        data += stub;
        length -= stub;
        fill = 0;
    }

    while (length >= 64) {
        process(data);
        data += 64;
        length -= 64;
    }

    if (length) std::memcpy(m_buffer + fill, data, length);
}

void PCSX::MD5::finish(uint8_t digest[16]) {
    uint8_t size[8];
    uint64_t bitLength = m_length * 8;

    size[0] = (bitLength >> 0) & 0xff;
    size[1] = (bitLength >> 8) & 0xff;
    size[2] = (bitLength >> 16) & 0xff;
    size[3] = (bitLength >> 24) & 0xff;
    size[4] = (bitLength >> 32) & 0xff;
    size[5] = (bitLength >> 40) & 0xff;
    size[6] = (bitLength >> 48) & 0xff;
    size[7] = (bitLength >> 56) & 0xff;

    static const uint8_t md5Padding[64] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    update(md5Padding, 1 + ((55 - m_length) & 0x3f));
    update(size, 8);

    digest[0] = (m_state[0] >> 0) & 0xff;
    digest[1] = (m_state[0] >> 8) & 0xff;
    digest[2] = (m_state[0] >> 16) & 0xff;
    digest[3] = (m_state[0] >> 24) & 0xff;
    digest[4] = (m_state[1] >> 0) & 0xff;
    digest[5] = (m_state[1] >> 8) & 0xff;
    digest[6] = (m_state[1] >> 16) & 0xff;
    digest[7] = (m_state[1] >> 24) & 0xff;
    digest[8] = (m_state[2] >> 0) & 0xff;
    digest[9] = (m_state[2] >> 8) & 0xff;
    digest[10] = (m_state[2] >> 16) & 0xff;
    digest[11] = (m_state[2] >> 24) & 0xff;
    digest[12] = (m_state[3] >> 0) & 0xff;
    digest[13] = (m_state[3] >> 8) & 0xff;
    digest[14] = (m_state[3] >> 16) & 0xff;
    digest[15] = (m_state[3] >> 24) & 0xff;
}

static inline uint32_t get32(const uint8_t* src, unsigned pos) {
    uint32_t ret = 0;
    ret <<= 8;
    ret |= src[pos + 3];
    ret <<= 8;
    ret |= src[pos + 2];
    ret <<= 8;
    ret |= src[pos + 1];
    ret <<= 8;
    ret |= src[pos + 0];
    return ret;
}

static constexpr inline uint32_t rotl(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }

static const uint32_t c_sine[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static constexpr inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static constexpr inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static constexpr inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static constexpr inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

#define SET(step, a, b, c, d, w, s, ac)      \
    {                                        \
        a += step(b, c, d) + w + c_sine[ac]; \
        a = rotl(a, s) + b;                  \
    }

void PCSX::MD5::process(const uint8_t* data) {
    uint32_t W[16], a, b, c, d;

    for (unsigned i = 0; i < 16; i++) W[i] = get32(data, i * 4);

    a = m_state[0];
    b = m_state[1];
    c = m_state[2];
    d = m_state[3];

    static constexpr unsigned S[4][4] = {
        {7, 12, 17, 22},
        {5, 9, 14, 20},
        {4, 11, 16, 23},
        {6, 10, 15, 21},
    };

    SET(F, a, b, c, d, W[0], S[0][0], 0);
    SET(F, d, a, b, c, W[1], S[0][1], 1);
    SET(F, c, d, a, b, W[2], S[0][2], 2);
    SET(F, b, c, d, a, W[3], S[0][3], 3);
    SET(F, a, b, c, d, W[4], S[0][0], 4);
    SET(F, d, a, b, c, W[5], S[0][1], 5);
    SET(F, c, d, a, b, W[6], S[0][2], 6);
    SET(F, b, c, d, a, W[7], S[0][3], 7);
    SET(F, a, b, c, d, W[8], S[0][0], 8);
    SET(F, d, a, b, c, W[9], S[0][1], 9);
    SET(F, c, d, a, b, W[10], S[0][2], 10);
    SET(F, b, c, d, a, W[11], S[0][3], 11);
    SET(F, a, b, c, d, W[12], S[0][0], 12);
    SET(F, d, a, b, c, W[13], S[0][1], 13);
    SET(F, c, d, a, b, W[14], S[0][2], 14);
    SET(F, b, c, d, a, W[15], S[0][3], 15);

    SET(G, a, b, c, d, W[1], S[1][0], 16);
    SET(G, d, a, b, c, W[6], S[1][1], 17);
    SET(G, c, d, a, b, W[11], S[1][2], 18);
    SET(G, b, c, d, a, W[0], S[1][3], 19);
    SET(G, a, b, c, d, W[5], S[1][0], 20);
    SET(G, d, a, b, c, W[10], S[1][1], 21);
    SET(G, c, d, a, b, W[15], S[1][2], 22);
    SET(G, b, c, d, a, W[4], S[1][3], 23);
    SET(G, a, b, c, d, W[9], S[1][0], 24);
    SET(G, d, a, b, c, W[14], S[1][1], 25);
    SET(G, c, d, a, b, W[3], S[1][2], 26);
    SET(G, b, c, d, a, W[8], S[1][3], 27);
    SET(G, a, b, c, d, W[13], S[1][0], 28);
    SET(G, d, a, b, c, W[2], S[1][1], 29);
    SET(G, c, d, a, b, W[7], S[1][2], 30);
    SET(G, b, c, d, a, W[12], S[1][3], 31);

    SET(H, a, b, c, d, W[5], S[2][0], 32);
    SET(H, d, a, b, c, W[8], S[2][1], 33);
    SET(H, c, d, a, b, W[11], S[2][2], 34);
    SET(H, b, c, d, a, W[14], S[2][3], 35);
    SET(H, a, b, c, d, W[1], S[2][0], 36);
    SET(H, d, a, b, c, W[4], S[2][1], 37);
    SET(H, c, d, a, b, W[7], S[2][2], 38);
    SET(H, b, c, d, a, W[10], S[2][3], 39);
    SET(H, a, b, c, d, W[13], S[2][0], 40);
    SET(H, d, a, b, c, W[0], S[2][1], 41);
    SET(H, c, d, a, b, W[3], S[2][2], 42);
    SET(H, b, c, d, a, W[6], S[2][3], 43);
    SET(H, a, b, c, d, W[9], S[2][0], 44);
    SET(H, d, a, b, c, W[12], S[2][1], 45);
    SET(H, c, d, a, b, W[15], S[2][2], 46);
    SET(H, b, c, d, a, W[2], S[2][3], 47);

    SET(I, a, b, c, d, W[0], S[3][0], 48);
    SET(I, d, a, b, c, W[7], S[3][1], 49);
    SET(I, c, d, a, b, W[14], S[3][2], 50);
    SET(I, b, c, d, a, W[5], S[3][3], 51);
    SET(I, a, b, c, d, W[12], S[3][0], 52);
    SET(I, d, a, b, c, W[3], S[3][1], 53);
    SET(I, c, d, a, b, W[10], S[3][2], 54);
    SET(I, b, c, d, a, W[1], S[3][3], 55);
    SET(I, a, b, c, d, W[8], S[3][0], 56);
    SET(I, d, a, b, c, W[15], S[3][1], 57);
    SET(I, c, d, a, b, W[6], S[3][2], 58);
    SET(I, b, c, d, a, W[13], S[3][3], 59);
    SET(I, a, b, c, d, W[4], S[3][0], 60);
    SET(I, d, a, b, c, W[11], S[3][1], 61);
    SET(I, c, d, a, b, W[2], S[3][2], 62);
    SET(I, b, c, d, a, W[9], S[3][3], 63);

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
}
