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

// Registration seam for the memory-card save-title encoder.
//
// The filesystem encodes save titles through the g_titleEncoder function
// pointer, which defaults to the lightweight ASCII-only encoder
// (Sjis::asciiToSjisTitle, ~190 bytes of table). A program that needs to write
// non-ASCII (e.g. Japanese) titles calls registerFullTitleEncoder() once at
// startup to swap in the complete UTF-8 -> Shift-JIS converter. Because the
// full encoder and its ~28kB table live in their own translation unit and are
// only reachable through registerFullTitleEncoder(), --gc-sections drops the
// table entirely from any program that never calls it.

namespace Sjis {

using TitleEncoder = uint32_t (*)(uint8_t* dst, uint32_t dstSize, const char* src);

// The active title encoder. Defaults to Sjis::asciiToSjisTitle.
extern TitleEncoder g_titleEncoder;

// Installs the full UTF-8 -> Shift-JIS title encoder (pulls in the ~28kB
// conversion table). Call once, before writing any non-ASCII title.
void registerFullTitleEncoder();

}  // namespace Sjis
