/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

namespace Mips {

// clang-format off
enum class Reg {
    R0, AT, V0, V1, A0, A1, A2, A3,  // 00 to 07
    T0, T1, T2, T3, T4, T5, T6, T7,  // 08 to 0f
    S0, S1, S2, S3, S4, S5, S6, S7,  // 10 to 17
    T8, T9, K0, K1, GP, SP, S8, RA,  // 18 to 1f
};
// clang-format on

typedef union {
    struct {
        uint32_t r0, at, v0, v1, a0, a1, a2, a3;
        uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
        uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
        uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
        uint32_t lo, hi;
    } n;
    uint32_t r[34]; /* Lo, Hi in r[32] and r[33] */
} GPRRegs;

}  // namespace Mips

// Make sure no packing is inserted anywhere
static_assert(sizeof(Mips::GPRRegs) == 34 * sizeof(uint32_t), "GPRRegs size mismatch");
