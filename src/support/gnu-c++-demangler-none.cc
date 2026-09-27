/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

// PEGTL does not build under libc++ (board #428), and the demangler is PEGTL's
// only consumer, so gnu-c++-demangler.cc is disabled on wasm. Its two callers -
// the assembly and callstacks widgets - are debugger UI that still compiles and
// links, so they need a definition.
//
// Returning the symbol unchanged is degraded, not a lie: that is already what
// the real demangler does for any name it cannot parse, so the UI renders a
// mangled name exactly as it would for an unrecognised one. It never reports a
// successful demangling that did not happen.
// #ifdef, not a feature macro: a #define in gnu-c++-demangler.cc is visible only
// inside that translation unit, so keying this file off one would compile BOTH
// definitions on desktop and fail the link with a duplicate symbol. It linked on
// wasm only because the macro was defined nowhere there.
#ifdef __EMSCRIPTEN__

#include "support/gnu-c++-demangler.h"

std::string PCSX::GNUDemangler::demangle(std::string_view symbol) { return std::string(symbol); }

#endif
