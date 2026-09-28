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

namespace PCSX {

// Runtime CPU capability probe. Query this before dispatching to any function
// compiled with [[gnu::target(...)]] or an equivalent: the compiler will happily
// emit AVX2 for such a function regardless of the baseline the rest of the binary
// was built with, and executing it on a machine without the feature is SIGILL.
//
// The AVX-family flags are deliberately conjunctions of the CPUID bit AND the
// XCR0 state-enable bits. A CPU can report AVX2 while the OS has not enabled
// YMM save/restore, in which case using it still faults. Checking the CPUID bit
// alone is the classic way to get this wrong.
struct CPUFeatures {
    // x86
    bool sse2 = false;
    bool ssse3 = false;
    bool sse41 = false;
    bool sse42 = false;
    bool avx = false;   // implies OS XMM+YMM state
    bool fma = false;
    bool avx2 = false;  // implies avx
    bool avx512f = false;
    bool avx512bw = false;
    // ARM
    bool neon = false;

    // Cached, computed once. Safe to call from any thread at any time.
    static const CPUFeatures &get();

    // Human readable list of what was detected, for logs and bug reports.
    static const char *describe();
};

}  // namespace PCSX
