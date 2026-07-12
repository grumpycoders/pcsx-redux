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

#include "utf8-decode.hh"

uint16_t Sjis::utf8Decode(const char* str, uint32_t length, uint32_t* index) {
    uint32_t i = *index;
    uint8_t c = str[i++];
    uint32_t cp;
    unsigned extra;
    if (c < 0x80) {
        *index = i;
        return c;
    } else if ((c & 0xe0) == 0xc0) {
        cp = c & 0x1f;
        extra = 1;
    } else if ((c & 0xf0) == 0xe0) {
        cp = c & 0x0f;
        extra = 2;
    } else {
        *index = i;
        return 0xfffd;
    }
    for (unsigned k = 0; k < extra; k++) {
        if (i >= length || (str[i] & 0xc0) != 0x80) {
            *index = i;
            return 0xfffd;
        }
        cp = (cp << 6) | (str[i++] & 0x3f);
    }
    *index = i;
    return cp > 0xffff ? 0xfffd : (uint16_t)cp;
}
