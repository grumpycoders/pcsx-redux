/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

#include <stdint.h>

#include "common/util/sjis-encode-table.h"
#include "common/util/utf8-decode.hh"

// Unicode -> Shift-JIS encoding, the inverse of support/sjis_conv.cc's decoder.
// Shares the same data as the forward table (sjis-table.h), inverted into
// sjis-encode-table.h. Usable from both the host and the MIPS targets.

namespace Sjis {

// Returns the Shift-JIS encoding of a Unicode codepoint, or 0 if it has no
// mapping. A result <= 0xff is a single byte; otherwise it is two bytes, high
// byte first. (U+0000 also returns 0, which is harmless for string use.)
static inline uint16_t unicodeToSjis(uint16_t unicode) {
    unsigned lo = 0, hi = sizeof(c_unicodeToSjisConvTable) / sizeof(c_unicodeToSjisConvTable[0]);
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        uint16_t u = c_unicodeToSjisConvTable[mid].unicode;
        if (u == unicode) return c_unicodeToSjisConvTable[mid].sjis;
        if (u < unicode) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

// utf8Decode() lives in common/util/utf8-decode.h (same Sjis namespace) so the
// lightweight encoders can share it without pulling in the conversion table.

// Encodes a UTF-8 C string to Shift-JIS. Writes up to dstSize bytes and returns
// the number written. Codepoints with no Shift-JIS mapping are emitted as '?'.
// The output is not NUL-terminated.
static inline uint32_t utf8ToSjis(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        uint16_t sjis = unicodeToSjis(cp);
        if (sjis == 0 && cp != 0) sjis = '?';
        if (sjis > 0xff) {
            if (out + 2 > dstSize) break;
            dst[out++] = sjis >> 8;
            dst[out++] = sjis & 0xff;
        } else {
            dst[out++] = sjis & 0xff;
        }
    }
    return out;
}

// Encodes a UTF-8 string to Shift-JIS using the BIOS save-title convention:
// printable ASCII is promoted to its fullwidth form (space -> U+3000,
// 0x21..0x7e -> U+ff01..U+ff5e) so it renders in the manager's fullwidth font,
// while any non-ASCII codepoint (e.g. Japanese) is encoded directly. This is
// what memory card save titles want. Writes up to dstSize bytes, returns the
// number written; output is not NUL-terminated.
static inline uint32_t utf8ToSjisTitle(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        if (cp == ' ') {
            cp = 0x3000;
        } else if (cp >= 0x21 && cp <= 0x7e) {
            cp = 0xff00 + (cp - 0x20);
        }
        uint16_t sjis = unicodeToSjis(cp);
        if (sjis == 0 && cp != 0) sjis = '?';
        if (sjis > 0xff) {
            if (out + 2 > dstSize) break;
            dst[out++] = sjis >> 8;
            dst[out++] = sjis & 0xff;
        } else {
            dst[out++] = sjis & 0xff;
        }
    }
    return out;
}

}  // namespace Sjis
