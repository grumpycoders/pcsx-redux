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

// r3000a.h already selects a dynarec per architecture and defines DYNAREC_NONE
// for every one it has no emitter for - i386, AA32, PPC, AA64-on-Windows, and
// the bare #else that wasm32 lands in. What it did not have was a
// Cpus::getDynaRec for that case: both recompiler.cc files define it inside
// their own arch guard, so DYNAREC_NONE targets had no definition at all.
//
// THE INCLUDE MUST COME BEFORE THE GUARD. DYNAREC_NONE is defined BY r3000a.h,
// so testing it above the include tests an undefined macro. My first version
// guarded on !DYNAREC_X86_64 && !DYNAREC_AA64 with the include inside, which is
// true everywhere at that point, so this file also defined getDynaRec on x86_64
// and the desktop link failed with a duplicate symbol. wasm was green throughout.
#include "core/r3000a.h"

#ifdef DYNAREC_NONE

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() { return nullptr; }

#endif
