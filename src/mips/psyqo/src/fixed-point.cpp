/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include "psyqo/fixed-point.hh"

void psyqo::FixedPointInternals::printInt(uint32_t value, const eastl::function<void(char)>& charPrinter,
                                          unsigned scale) {
    uint32_t integer = value / scale;
    uint32_t fractional = value - (integer * scale);
    if (integer == 0) {
        charPrinter('0');
    } else {
        char out[12];
        char* ptr = out;
        while (integer) {
            auto digit = integer % 10;
            integer /= 10;
            *ptr++ = digit + '0';
        }
        while (ptr != out) {
            charPrinter(*--ptr);
        }
    }
    if (fractional == 0) return;
    charPrinter('.');
    for (unsigned i = 0; i < 5; i++) {
        fractional *= 10;
        uint32_t copy = fractional;
        copy /= scale;
        fractional -= copy * scale;
        charPrinter((copy % 10) + '0');
        if (fractional == 0) return;
    }
}
