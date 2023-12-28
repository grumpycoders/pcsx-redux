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

#include <stdint.h>

namespace psyqo {

namespace GTE {

/**
 * @brief The GTE math kernels.
 *
 * @details This namespace contains all of the PS1 GTE math kernels.
 * They are not necessarily meant to be used directly, but they are
 * still exposed publicly as they may be useful to some. Their usage
 * is delicate, as the compiler will not be able to understand the
 * interlocking nature of the GTE, and thus will not be able to add
 * the necessary hazard stalls. This means that the programmer must
 * be careful to add the necessary stalls themselves.
 */
namespace Kernels {

// Shift factor: Unsigned (no change) or Shifted (>> 12)
enum SF : unsigned { Unshifted, Shifted };
// Low limit: Unlimited (-2^15) or Limited (0)
enum LM : unsigned { Unlimited, Limited };

// Coordinate and Perspective Transformation
//   pers(([rt]·[v0]) >> 12 + [tr]) -> sxy2
//     14 cycles
static inline void rtps() { asm volatile("cop2 0x0180001"); }
//   pers(([rt]·[v0]) >> 12 + [tr]) -> sxy0
//   pers(([rt]·[v1]) >> 12 + [tr]) -> sxy1
//   pers(([rt]·[v2]) >> 12 + [tr]) -> sxy2
//     22 cycles
static inline void rtpt() { asm volatile("cop2 0x0280030"); }

// Depth Queuing
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb, lv, sv
//     8 cycles
static inline void dpcl() { asm volatile("cop2 0x0680029"); }
//   (1 - dp)·[rgb] + dp·[fc] -> rgb, lv, sv
//     8 cycles
static inline void dpcs() { asm volatile("cop2 0x0780010"); }
//   (1 - dp)·[rgb0] + dp·[fc] -> rgb0, lv, sv
//   (1 - dp)·[rgb1] + dp·[fc] -> rgb1, lv, sv
//   (1 - dp)·[rgb2] + dp·[fc] -> rgb2, lv, sv
//     17 cycles
static inline void dpct() { asm volatile("cop2 0x0f8002a"); }

// Interpolation
//   (1 - dp)·[sv] + dp·[fc] -> rgb2, lv, sv
//     8 cycles
static inline void intpl() { asm volatile("cop2 0x0980011"); }

// Termwise Vector Square
//   [sv.x² >> 12, sv.y² >> 12, sv.z² >> 12] -> lv, sv
//     5 cycles
template <SF sf = Shifted>
static inline void sqr() {
    if constexpr (sf == Shifted) {
        asm volatile("cop2 0x0a80428");
    } else {
        asm volatile("cop2 0x0a00428");
    }
}

// Light Source Calculations
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> rgb2
//     14 cycles
static inline void ncs() { asm volatile("cop2 0x0c8041e"); }
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> rgb0
//   limit(([ll]·[v1]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> rgb1
//   limit(([ll]·[v2]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> rgb2
//     30 cycles
static inline void nct() { asm volatile("cop2 0x0d80420"); }
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb2
//     19 cycles
static inline void ncds() { asm volatile("cop2 0x0e80413"); }
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb0
//   limit(([ll]·[v1]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb1
//   limit(([ll]·[v2]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb2
//     44 cycles
static inline void ncdt() { asm volatile("cop2 0x0f80416"); }
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   [rgb·sv] -> rgb2
//     17 cycles
static inline void nccs() { asm volatile("cop2 0x0108041b"); }
//   limit(([ll]·[v0]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   [rgb·sv] -> rgb0
//   limit(([ll]·[v1]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   [rgb·sv] -> rgb1
//   limit(([ll]·[v2]) >> 12) -> sv
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   [rgb·sv] -> rgb2
//     39 cycles
static inline void ncct() { asm volatile("cop2 0x0118043f"); }
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   (1 - dp)·[rgb·sv] + dp·[fc] -> rgb2
//     13 cycles
static inline void cdp() { asm volatile("cop2 0x01280414"); }
//   limit(([lc]·[sv]) >> 12) + [bk] -> sv
//   [rgb·sv] -> rgb2
//     11 cycles
static inline void cc() { asm volatile("cop2 0x0138041c"); }

// Normal Clipping
//   sx0*sy1 + sx1*sy2 + sx2*sy0 - sx0*sy2 - sx1*sy0 - sx2*sy1 -> opz
//   aka determinant of the matrix
//     [sx1 - sx0, sy1 - sy0]
//     [sx2 - sx0, sy2 - sy0]
//     8 cycles
static inline void nclip() { asm volatile("cop2 0x01400006"); }

// Z Average
//   zsf3 * (sz0 + sz1 + sz2) -> otz
//     5 cycles
static inline void avsz3() { asm volatile("cop2 0x0158002d"); }
//   zsf4 * (sz0 + sz1 + sz2 + sz4) -> otz
//     6 cycles
static inline void avsz4() { asm volatile("cop2 0x0168002e"); }

// Cross Product (improperly named Outer Product in Sony's lingo)
//   rt.22 * ir3 - rt.33 * ir2 -> ir1
//   rt.33 * ir1 - rt.11 * ir3 -> ir2
//   rt.11 * ir2 - rt.22 * ir1 -> ir3
//     6 cycles
template <SF sf = Shifted>
static inline void cp() {
    if constexpr (sf == Shifted) {
        asm volatile("cop2 0x0178000c");
    } else {
        asm volatile("cop2 0x0170000c");
    }
}

// General Interpolation
//   dp·[sv] -> lv, sv
//     5 cycles
template <SF sf = Shifted>
static inline void gpf() {
    if constexpr (sf == Shifted) {
        asm volatile("cop2 0x0198003d");
    } else {
        asm volatile("cop2 0x0190003d");
    }
}
//   [lv] + dp·[sv] -> lv, sv
//     5 cycles
template <SF sf = Shifted>
static inline void gpl() {
    if constexpr (sf == Shifted) {
        asm volatile("cop2 0x01a8003e");
    } else {
        asm volatile("cop2 0x01a0003e");
    }
}

// All of the MVMVA operations take 8 cycles to complete.
// The MVMVA operation is the basis for the matrix math operations.
// The functions defined right underneath are simply aliases. They
// are provided for convenience, as programmers may know them from
// the original PS1 SDK documentation, but using the MVMVA operation
// directly may actually be more readable.
// Multiplication Matrix: Rotation, Light Source Direction, Light Source Color
enum class MX : unsigned { RT, LL, LC };
// Multiplication Vector
enum class MV : unsigned { V0, V1, V2, IR };
// Translation Vector: Translation, Back Color, Front Color, Zero
enum class TV : unsigned { TR, BK, FC, Zero };
template <MX mx, MV v, TV cv = TV::Zero, SF sf = Shifted, LM lm = Unlimited>
void mvmva() {
    constexpr uint32_t op =
        (4 << 20) | (sf << 19) | (uint32_t(mx) << 17) | (uint32_t(v) << 15) | (uint32_t(cv) << 13) | (lm << 10) | 18;
    asm volatile("cop2 %0" : : "i"(op));
}

// Coordinate Conversion, Light Source Calculations
//   ([rt]·[v0]) >> 12 + [tr] -> lv, sv
static inline void rt() { mvmva<MX::RT, MV::V0, TV::TR>(); }
//   limit(([ll]·[v0]) >> 12) -> lv, sv
static inline void ll() { mvmva<MX::LL, MV::V0, TV::Zero, SF::Shifted, LM::Limited>(); }
//   limit(([lc]·[sv]) >> 12) + [bk] -> lv, sv
static inline void lc() { mvmva<MX::LC, MV::IR, TV::BK, SF::Shifted, LM::Limited>(); }
//   [rt]·[sv] -> lv
static inline void rtir_sf0() { mvmva<MX::RT, MV::IR, TV::Zero, SF::Unshifted>(); }

// General Matrix Operations
//   ([rt]·[v0]) >> 12 -> lv, sv
static inline void rtv0() { mvmva<MX::RT, MV::V0, TV::Zero>(); }
//   ([rt]·[v1]) >> 12 -> lv, sv
static inline void rtv1() { mvmva<MX::RT, MV::V1, TV::Zero>(); }
//   ([rt]·[v2]) >> 12 -> lv, sv
static inline void rtv2() { mvmva<MX::RT, MV::V2, TV::Zero>(); }
//   ([rt]·[sv]) >> 12 -> lv, sv
static inline void rtir() { mvmva<MX::RT, MV::IR, TV::Zero>(); }
//   ([rt]·[v0]) >> 12 + [tr] -> lv, sv
static inline void rtv0tr() { mvmva<MX::RT, MV::V0, TV::TR>(); }
//   ([rt]·[v1]) >> 12 + [tr] -> lv, sv
static inline void rtv1tr() { mvmva<MX::RT, MV::V1, TV::TR>(); }
//   ([rt]·[v2]) >> 12 + [tr] -> lv, sv
static inline void rtv2tr() { mvmva<MX::RT, MV::V2, TV::TR>(); }
//   ([rt]·[sv]) >> 12 + [tr] -> lv, sv
static inline void rtirtr() { mvmva<MX::RT, MV::IR, TV::TR>(); }
//   ([rt]·[v0]) >> 12 + [bk] -> lv, sv
static inline void rtv0bk() { mvmva<MX::RT, MV::V0, TV::BK>(); }
//   ([rt]·[v1]) >> 12 + [bk] -> lv, sv
static inline void rtv1bk() { mvmva<MX::RT, MV::V1, TV::BK>(); }
//   ([rt]·[v2]) >> 12 + [bk] -> lv, sv
static inline void rtv2bk() { mvmva<MX::RT, MV::V2, TV::BK>(); }
//   ([rt]·[sv]) >> 12 + [bk] -> lv, sv
static inline void rtirbk() { mvmva<MX::RT, MV::IR, TV::BK>(); }
//   ([rt]·[v0]) >> 12 + [fc] -> lv, sv
static inline void rtv0fc() { mvmva<MX::RT, MV::V0, TV::FC>(); }
//   ([rt]·[v1]) >> 12 + [fc] -> lv, sv
static inline void rtv1fc() { mvmva<MX::RT, MV::V1, TV::FC>(); }
//   ([rt]·[v2]) >> 12 + [fc] -> lv, sv
static inline void rtv2fc() { mvmva<MX::RT, MV::V2, TV::FC>(); }
//   ([rt]·[sv]) >> 12 + [fc] -> lv, sv
static inline void rtirfc() { mvmva<MX::RT, MV::IR, TV::FC>(); }
//   ([ll]·[v0]) >> 12 -> lv, sv
static inline void llv0() { mvmva<MX::LL, MV::V0, TV::Zero>(); }
//   ([ll]·[v1]) >> 12 -> lv, sv
static inline void llv1() { mvmva<MX::LL, MV::V1, TV::Zero>(); }
//   ([ll]·[v2]) >> 12 -> lv, sv
static inline void llv2() { mvmva<MX::LL, MV::V2, TV::Zero>(); }
//   ([ll]·[sv]) >> 12 -> lv, sv
static inline void llir() { mvmva<MX::LL, MV::IR, TV::Zero>(); }
//   ([ll]·[v0]) >> 12 + [tr] -> lv, sv
static inline void llv0tr() { mvmva<MX::LL, MV::V0, TV::TR>(); }
//   ([ll]·[v1]) >> 12 + [tr] -> lv, sv
static inline void llv1tr() { mvmva<MX::LL, MV::V1, TV::TR>(); }
//   ([ll]·[v2]) >> 12 + [tr] -> lv, sv
static inline void llv2tr() { mvmva<MX::LL, MV::V2, TV::TR>(); }
//   ([ll]·[sv]) >> 12 + [tr] -> lv, sv
static inline void llirtr() { mvmva<MX::LL, MV::IR, TV::TR>(); }
//   ([ll]·[v0]) >> 12 + [bk] -> lv, sv
static inline void llv0bk() { mvmva<MX::LL, MV::V0, TV::BK>(); }
//   ([ll]·[v1]) >> 12 + [bk] -> lv, sv
static inline void llv1bk() { mvmva<MX::LL, MV::V1, TV::BK>(); }
//   ([ll]·[v2]) >> 12 + [bk] -> lv, sv
static inline void llv2bk() { mvmva<MX::LL, MV::V2, TV::BK>(); }
//   ([ll]·[sv]) >> 12 + [bk] -> lv, sv
static inline void llirbk() { mvmva<MX::LL, MV::IR, TV::BK>(); }
//   ([ll]·[v0]) >> 12 + [fc] -> lv, sv
static inline void llv0fc() { mvmva<MX::LL, MV::V0, TV::FC>(); }
//   ([ll]·[v1]) >> 12 + [fc] -> lv, sv
static inline void llv1fc() { mvmva<MX::LL, MV::V1, TV::FC>(); }
//   ([ll]·[v2]) >> 12 + [fc] -> lv, sv
static inline void llv2fc() { mvmva<MX::LL, MV::V2, TV::FC>(); }
//   ([ll]·[sv]) >> 12 + [fc] -> lv, sv
static inline void llirfc() { mvmva<MX::LL, MV::IR, TV::FC>(); }
//   ([lc]·[v0]) >> 12 -> lv, sv
static inline void lcv0() { mvmva<MX::LC, MV::V0, TV::Zero>(); }
//   ([lc]·[v1]) >> 12 -> lv, sv
static inline void lcv1() { mvmva<MX::LC, MV::V1, TV::Zero>(); }
//   ([lc]·[v2]) >> 12 -> lv, sv
static inline void lcv2() { mvmva<MX::LC, MV::V2, TV::Zero>(); }
//   ([lc]·[sv]) >> 12 -> lv, sv
static inline void lcir() { mvmva<MX::LC, MV::IR, TV::Zero>(); }
//   ([lc]·[v0]) >> 12 + [tr] -> lv, sv
static inline void lcv0tr() { mvmva<MX::LC, MV::V0, TV::TR>(); }
//   ([lc]·[v1]) >> 12 + [tr] -> lv, sv
static inline void lcv1tr() { mvmva<MX::LC, MV::V1, TV::TR>(); }
//   ([lc]·[v2]) >> 12 + [tr] -> lv, sv
static inline void lcv2tr() { mvmva<MX::LC, MV::V2, TV::TR>(); }
//   ([lc]·[sv]) >> 12 + [tr] -> lv, sv
static inline void lcirtr() { mvmva<MX::LC, MV::IR, TV::TR>(); }
//   ([lc]·[v0]) >> 12 + [bk] -> lv, sv
static inline void lcv0bk() { mvmva<MX::LC, MV::V0, TV::BK>(); }
//   ([lc]·[v1]) >> 12 + [bk] -> lv, sv
static inline void lcv1bk() { mvmva<MX::LC, MV::V1, TV::BK>(); }
//   ([lc]·[v2]) >> 12 + [bk] -> lv, sv
static inline void lcv2bk() { mvmva<MX::LC, MV::V2, TV::BK>(); }
//   ([lc]·[sv]) >> 12 + [bk] -> lv, sv
static inline void lcirbk() { mvmva<MX::LC, MV::IR, TV::BK>(); }
//   ([lc]·[v0]) >> 12 + [fc] -> lv, sv
static inline void lcv0fc() { mvmva<MX::LC, MV::V0, TV::FC>(); }
//   ([lc]·[v1]) >> 12 + [fc] -> lv, sv
static inline void lcv1fc() { mvmva<MX::LC, MV::V1, TV::FC>(); }
//   ([lc]·[v2]) >> 12 + [fc] -> lv, sv
static inline void lcv2fc() { mvmva<MX::LC, MV::V2, TV::FC>(); }
//   ([lc]·[sv]) >> 12 + [fc] -> lv, sv
static inline void lcirfc() { mvmva<MX::LC, MV::IR, TV::FC>(); }

}  // namespace Kernels

}  // namespace GTE

}  // namespace psyqo
