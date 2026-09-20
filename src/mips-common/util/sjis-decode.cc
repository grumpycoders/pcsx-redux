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

#include "sjis-decode.hh"

#include "sjis-fullwidth-ascii.hh"
#include "sjis-table.h"

uint32_t Sjis::sjisToUtf8(char* dst, uint32_t dstSize, const uint8_t* src, uint32_t srcLen) {
    constexpr uint32_t tableSize = sizeof(c_sjisToUnicodeConvTable) / sizeof(c_sjisToUnicodeConvTable[0]);
    if (dstSize == 0) return 0;
    uint32_t out = 0;
    for (uint32_t i = 0; i < srcLen; i++) {
        uint8_t c = src[i];
        if (c == 0) break;  // NUL terminates; 0x00 is never a Shift-JIS lead/trail byte.
        uint32_t index = 0;
        switch (c >> 4) {
            case 8:
                index = 0x100;
                break;
            case 9:
                index = 0x1100;
                break;
            case 14:
                index = 0x2100;
                break;
        }
        if (index != 0) {
            index += (c & 0x0f) << 8;
            if (++i >= srcLen) break;  // truncated trailing lead byte: drop it.
            c = src[i];
        }
        index += c;
        if (index >= tableSize) continue;
        uint16_t v = c_sjisToUnicodeConvTable[index];
        if (v < 0x80) {
            if (out + 1 >= dstSize) break;
            dst[out++] = static_cast<char>(v);
        } else if (v < 0x800) {
            if (out + 2 >= dstSize) break;
            dst[out++] = static_cast<char>(0xc0 | (v >> 6));
            dst[out++] = static_cast<char>(0x80 | (v & 0x3f));
        } else {
            if (out + 3 >= dstSize) break;
            dst[out++] = static_cast<char>(0xe0 | (v >> 12));
            dst[out++] = static_cast<char>(0x80 | ((v & 0xfff) >> 6));
            dst[out++] = static_cast<char>(0x80 | (v & 0x3f));
        }
    }
    dst[out] = '\0';
    return out;
}
