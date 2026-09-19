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

// __clzsi2 is what gcc emits a call to for __builtin_clz on this target, since
// mips1 has no count-leading-zeros opcode - that is MIPS32 and the console
// predates it. Builds here are -nostdlib, so without this file __builtin_clz is
// an undefined reference rather than a slow path, and with it every user of the
// builtin gets the GTE.
//
// GTE LZCS/LZCR is the only count-leading hardware on the machine. Two things
// about it that the implementation below is entirely made of:
//
//  - It counts leading bits EQUAL TO THE SIGN BIT, so it answers leading zeros
//    only for a non-negative input: on 0x80000000 it returns 1, not 0. The sign
//    test is that correction, not an optimisation.
//  - It does not interlock, so the write and the read each need two dummy
//    opcodes after them; cop2_put and cop2_get carry those. One is not enough -
//    the read comes back with the previous write's answer roughly a third of the
//    time, and a single isolated call passes by luck.
//
// REQUIRES COP2 ENABLED (SR bit 30, CU2). Both the retail BIOS, as a side effect
// of its shell, and OpenBIOS, which sets it deliberately for that reason, leave
// it on before any user code runs. Code that clears SR itself must re-enable it
// or override this weak symbol.
//
// Note this is MORE defined than the libgcc version it replaces: LZCR(0) is 32,
// where __builtin_clz(0) is undefined. Do not rely on that in portable code.

#include <stdint.h>

#include "common/hardware/cop2.h"

__attribute__((weak)) int __clzsi2(unsigned int x) {
    uint32_t r;
    if ((int32_t)x < 0) return 0;
    cop2_put(COP2_LZCS, x);
    cop2_get(COP2_LZCR, r);
    return (int)r;
}
