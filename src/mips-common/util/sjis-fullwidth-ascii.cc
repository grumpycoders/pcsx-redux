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

#include "sjis-fullwidth-ascii.hh"

#include "utf8-decode.hh"

const uint16_t Sjis::c_fullwidthAsciiToSjis[96] = {
    0x8140,  // space
    0x8149,  // !
    0x8168,  // "
    0x8194,  // #
    0x8190,  // $
    0x8193,  // %
    0x8195,  // &
    0x8166,  // '
    0x8169,  // (
    0x816a,  // )
    0x8196,  // *
    0x817b,  // +
    0x8143,  // ,
    0x817c,  // -
    0x8144,  // .
    0x815e,  // /
    0x824f,  // 0
    0x8250,  // 1
    0x8251,  // 2
    0x8252,  // 3
    0x8253,  // 4
    0x8254,  // 5
    0x8255,  // 6
    0x8256,  // 7
    0x8257,  // 8
    0x8258,  // 9
    0x8146,  // :
    0x8147,  // ;
    0x8183,  // <
    0x8181,  // =
    0x8184,  // >
    0x8148,  // ?
    0x8197,  // @
    0x8260,  // A
    0x8261,  // B
    0x8262,  // C
    0x8263,  // D
    0x8264,  // E
    0x8265,  // F
    0x8266,  // G
    0x8267,  // H
    0x8268,  // I
    0x8269,  // J
    0x826a,  // K
    0x826b,  // L
    0x826c,  // M
    0x826d,  // N
    0x826e,  // O
    0x826f,  // P
    0x8270,  // Q
    0x8271,  // R
    0x8272,  // S
    0x8273,  // T
    0x8274,  // U
    0x8275,  // V
    0x8276,  // W
    0x8277,  // X
    0x8278,  // Y
    0x8279,  // Z
    0x816d,  // [
    0x815f,  // backslash
    0x816e,  // ]
    0x814f,  // ^
    0x8151,  // _
    0x8165,  // `
    0x8281,  // a
    0x8282,  // b
    0x8283,  // c
    0x8284,  // d
    0x8285,  // e
    0x8286,  // f
    0x8287,  // g
    0x8288,  // h
    0x8289,  // i
    0x828a,  // j
    0x828b,  // k
    0x828c,  // l
    0x828d,  // m
    0x828e,  // n
    0x828f,  // o
    0x8290,  // p
    0x8291,  // q
    0x8292,  // r
    0x8293,  // s
    0x8294,  // t
    0x8295,  // u
    0x8296,  // v
    0x8297,  // w
    0x8298,  // x
    0x8299,  // y
    0x829a,  // z
    0x816f,  // {
    0x8162,  // |
    0x8170,  // }
    0x8160,  // ~
    0x0000,  // DEL
};

uint32_t Sjis::asciiToSjisTitle(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        uint16_t sjis;
        if (cp == ' ') {
            sjis = c_fullwidthAsciiToSjis[0];
        } else if (cp >= 0x21 && cp <= 0x7e) {
            sjis = c_fullwidthAsciiToSjis[cp - 0x20];
        } else {
            sjis = 0;
        }
        if (sjis == 0) sjis = '?';
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

uint32_t Sjis::sjisTitleToAscii(char* dst, uint32_t dstSize, const uint8_t* src, uint32_t srcLen) {
    if (dstSize == 0) return 0;
    uint32_t out = 0;
    for (uint32_t i = 0; i < srcLen; i++) {
        uint8_t c = src[i];
        if (c == 0) break;
        char ch;
        unsigned hi = c >> 4;
        if (hi == 8 || hi == 9 || hi == 14) {
            // Two-byte lead: reverse-lookup its fullwidth mapping.
            if (++i >= srcLen) break;  // truncated trailing lead byte: drop it.
            uint16_t sjis = (static_cast<uint16_t>(c) << 8) | src[i];
            ch = '?';
            for (unsigned k = 0; k < 95; k++) {
                if (c_fullwidthAsciiToSjis[k] == sjis) {
                    ch = static_cast<char>(0x20 + k);
                    break;
                }
            }
        } else if (c >= 0x20 && c <= 0x7e) {
            ch = static_cast<char>(c);  // already plain ASCII: pass through.
        } else {
            ch = '?';
        }
        if (out + 1 >= dstSize) break;
        dst[out++] = ch;
    }
    dst[out] = '\0';
    return out;
}
