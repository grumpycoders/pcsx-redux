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

#include "support/sjis_conv.h"

#include "mips/common/util/sjis-table.h"

std::string PCSX::Sjis::toUtf8(const std::string_view& str) {
    std::string ret;
    constexpr unsigned tableSize = sizeof(c_sjisToUnicodeConvTable) / sizeof(c_sjisToUnicodeConvTable[0]);
    for (size_t i = 0; i < str.length(); i++) {
        uint8_t c = str[i];
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
            i++;
            if (i >= str.length()) break;
            c = str[i];
        }

        index += c;

        if (index >= tableSize) continue;
        uint16_t v = c_sjisToUnicodeConvTable[index];
        if (v < 0x80) {
            ret += v;
        } else if (v < 0x800) {
            ret += 0xc0 | (v >> 6);
            ret += 0x80 | (v & 0x3f);
        } else {
            ret += 0xe0 | (v >> 12);
            ret += 0x80 | ((v & 0xfff) >> 6);
            ret += 0x80 | (v & 0x3f);
        }
    }

    return ret;
}
