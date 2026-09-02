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

// Every other target has exactly one dynarec, and each recompiler.cc defines
// Cpus::getDynaRec inside its own arch guard. wasm has none - the x64 emitter is
// xbyak and the aa64 one is vixl, both of which emit host machine code - so
// without this file getDynaRec has no definition at all on any arch that is
// neither DYNAREC_X86_64 nor DYNAREC_AA64.
//
// The condition is deliberately the negation of the two arch guards rather than
// __EMSCRIPTEN__: the gap is "no dynarec for this architecture", which is a more
// general fact than "this is a wasm build", and a future target hits it too.
#if !defined(DYNAREC_X86_64) && !defined(DYNAREC_AA64)

#include "core/r3000a.h"

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() { return nullptr; }

#endif
