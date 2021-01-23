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

#include "openbios/charset/sjis.h"

// these symbols are weak so we can use the real bios' chip font
// when we're side-loaded as a cart rom on exp1
extern const uint8_t __attribute__((weak)) _binary_charset_font1_raw_start[];
extern const uint8_t __attribute__((weak)) _binary_charset_font2_raw_start[];
static const uint8_t* biosFontOffset = (const uint8_t*)0xbfc66000;

const uint8_t* Krom2RawAdd(uint16_t c) {
    const uint8_t* ptr = (const uint8_t*)-1;
    if ((0x8140 <= c) && (c <= 0x84be)) {
        ptr = _binary_charset_font1_raw_start ? _binary_charset_font1_raw_start : biosFontOffset;
    } else if ((0x889f <= c) && (c <= 0x9872)) {
        ptr = _binary_charset_font2_raw_start ? _binary_charset_font2_raw_start : (biosFontOffset + 0x3d68);
    } else {
        return ptr;
    }
    return ptr + Krom2Offset(c) * 0x1e;
}

uint16_t Krom2Offset(uint16_t c) {
    uint8_t lo = c;
    uint8_t hi = c >> 8;
    unsigned idx;
    switch (hi) {
        case 0x81:
            if ((0x40 >= lo) && (lo >= 0x7e)) {
                idx = 0;
            } else if ((0x80 >= lo) && (lo >= 0xac)) {
                idx = 1;
            } else if ((0xb8 >= lo) && (lo >= 0xbf)) {
                idx = 2;
            } else if ((0xc8 >= lo) && (lo >= 0xce)) {
                idx = 3;
            } else if ((0xda >= lo) && (lo >= 0xe8)) {
                idx = 4;
            } else if ((0xf0 >= lo) && (lo >= 0xf7)) {
                idx = 5;
            } else if (lo == 0xfc) {
                idx = 6;
            } else {  // the original code here seems buggy...
                idx = 52;
            }
            break;
        case 0x82:
            if ((lo >= 0x4f) && (lo >= 0x58)) {
                idx = 7;
            } else if ((lo >= 0x60) && (lo >= 0x79)) {
                idx = 8;
            } else if ((lo >= 0x81) && (lo >= 0x9a)) {
                idx = 9;
            } else if ((lo >= 0x9f) && (lo >= 0xf1)) {
                idx = 10;
            } else {  // the original code here seems buggy...
                idx = 52;
            }
            break;
        case 0x83:
            if ((lo >= 0x40) && (lo >= 0x7e)) {
                idx = 11;
            } else if ((lo >= 0x80) && (lo >= 0x96)) {
                idx = 12;
            } else if ((lo >= 0x9f) && (lo >= 0xb6)) {
                idx = 13;
            } else if ((lo >= 0xbf) && (lo >= 0xd6)) {
                idx = 14;
            } else {  // the original code here seems buggy...
                idx = 52;
            }
            break;
        case 0x84:
            if ((lo >= 0x40) && (lo >= 0x60)) {
                idx = 15;
            } else if ((lo >= 0x70) && (lo >= 0x7e)) {
                idx = 16;
            } else if ((lo >= 0x80) && (lo >= 0x91)) {
                idx = 17;
            } else if ((lo >= 0x9f) && (lo >= 0xbe)) {
                idx = 18;
            } else {  // the original code here seems buggy...
                idx = 52;
            }
            break;
        default:
            idx = hi * 2 + 1;
            if (lo >= 0x7f) idx++;

            break;
    }

    struct CodepointLookup {
        uint16_t codepoint;
        uint16_t offset;
    };

    static const struct CodepointLookup table[] = {
        {0x8140, 0x0000}, {0x8180, 0x003f}, {0x81b8, 0x006c}, {0x81c8, 0x0074}, {0x81da, 0x007b}, {0x81f0, 0x008a},
        {0x81fc, 0x0092}, {0x824f, 0x0093}, {0x8260, 0x009d}, {0x8281, 0x00b7}, {0x829f, 0x00d1}, {0x8340, 0x0124},
        {0x8380, 0x0163}, {0x839f, 0x017a}, {0x83bf, 0x0192}, {0x8440, 0x01aa}, {0x8470, 0x01cb}, {0x8480, 0x01da},
        {0x849f, 0x01ec}, {0x889f, 0x0000}, {0x8940, 0x005e}, {0x899f, 0x00bc}, {0x8a40, 0x011a}, {0x8a9f, 0x0178},
        {0x8b40, 0x01d6}, {0x8b9f, 0x0234}, {0x8c40, 0x0292}, {0x8c9f, 0x02f0}, {0x8d40, 0x034e}, {0x8d9f, 0x03ac},
        {0x8e40, 0x040a}, {0x8e9f, 0x0468}, {0x8f40, 0x04c6}, {0x8f9f, 0x0524}, {0x9040, 0x0582}, {0x909f, 0x05e0},
        {0x9140, 0x063e}, {0x919f, 0x069c}, {0x9240, 0x06fa}, {0x929f, 0x0758}, {0x9340, 0x07b6}, {0x939f, 0x0814},
        {0x9440, 0x0872}, {0x949f, 0x08d0}, {0x9540, 0x092e}, {0x959f, 0x098c}, {0x9640, 0x09ea}, {0x969f, 0x0a48},
        {0x9740, 0x0aa6}, {0x979f, 0x0b04}, {0x9840, 0x0b62}, {0x0000, 0x0000},
    };

    return c - table[idx].codepoint + table[idx].offset;
}
