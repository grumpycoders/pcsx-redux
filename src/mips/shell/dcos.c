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

#include "shell/dcos.h"

#include <stdint.h>

// 2kB
int32_t g_cosTable[512];

void generateCosTable() {
    // f(n) = cos(n * 2pi / 2048)
    // f(n) = 2 * f(1) * f(n - 1) - f(n - 2)
    g_cosTable[0] = 16777216;             // 2^24 * cos(0 * 2pi / 2048)
    static const long long C = 16777137;  // 2^24 * cos(1 * 2pi / 2048) = C = f(1);
    g_cosTable[1] = C;

    for (int i = 2; i < 511; i++) {
        g_cosTable[i] = ((C * g_cosTable[i - 1]) >> 23) - g_cosTable[i - 2];
    }

    // the approximation is a bit too steep, so this value would otherwise
    // get slightly negative
    g_cosTable[511] = 0;
}
