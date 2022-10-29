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

#include "psyqo/msf.hh"

psyqo::MSF::MSF(uint32_t lba) {
    m = lba / 75 / 60;
    lba = lba - m * 75 * 60;
    s = lba / 75;
    lba = lba - s * 75;
    f = lba;
}

auto psyqo::MSF::operator<=>(const MSF &other) const {
    if (m != other.m) return m <=> other.m;
    if (s != other.s) return s <=> other.s;
    return f <=> other.f;
}

psyqo::MSF &psyqo::MSF::operator++() {
    f++;
    if (f >= 75) {
        f = 0;
        s++;
        if (s >= 60) {
            s = 0;
            m++;
        }
    }
    return *this;
}
