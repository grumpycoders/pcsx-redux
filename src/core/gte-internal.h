/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

// GTE internal implementation header.
//
// Shared by gte-transfer.cc and gte-instructions.cc. Not part of the public
// interface. Contains register accessors, arithmetic helpers, limiter functions,
// and pipeline stage templates - everything that the GTE instruction
// implementations need but callers of the GTE class do not.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

#include "core/gte.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "support/table-generator.h"

namespace PCSX {
namespace GTEImpl {

// ============================================================================
// 44-bit accumulator with per-addition overflow tracking
// ============================================================================

class int44 {
  public:
    int44(int64_t value)
        : m_value(value),
          m_posOverflow(value > INT64_C(0x7ffffffffff)),
          m_negOverflow(value < INT64_C(-0x80000000000)) {}

    int44(int64_t value, bool posOverflow, bool negOverflow)
        : m_value(value), m_posOverflow(posOverflow), m_negOverflow(negOverflow) {}

    int44 operator+(int64_t rhs) const {
        int64_t result = ((m_value + rhs) << 20) >> 20;
        return int44(result, m_posOverflow || (result < 0 && m_value >= 0 && rhs >= 0),
                     m_negOverflow || (result >= 0 && m_value < 0 && rhs < 0));
    }

    bool positiveOverflow() const { return m_posOverflow; }
    bool negativeOverflow() const { return m_negOverflow; }
    int64_t value() const { return m_value; }

  private:
    int64_t m_value;
    bool m_posOverflow;
    bool m_negOverflow;
};

// ============================================================================
// FLAG register bit definitions
// ============================================================================

namespace Flag {
constexpr uint32_t GTE_ERROR = 1u << 31;
constexpr uint32_t MAC1_POS = GTE_ERROR | (1u << 30);
constexpr uint32_t MAC1_NEG = GTE_ERROR | (1u << 27);
constexpr uint32_t MAC2_POS = GTE_ERROR | (1u << 29);
constexpr uint32_t MAC2_NEG = GTE_ERROR | (1u << 26);
constexpr uint32_t MAC3_POS = GTE_ERROR | (1u << 28);
constexpr uint32_t MAC3_NEG = GTE_ERROR | (1u << 25);
constexpr uint32_t IR1_SAT = GTE_ERROR | (1u << 24);
constexpr uint32_t IR2_SAT = GTE_ERROR | (1u << 23);
constexpr uint32_t IR3_SAT = 1u << 22;
constexpr uint32_t COLOR_R_SAT = 1u << 21;
constexpr uint32_t COLOR_G_SAT = 1u << 20;
constexpr uint32_t COLOR_B_SAT = 1u << 19;
constexpr uint32_t SZ_SAT = GTE_ERROR | (1u << 18);
constexpr uint32_t DIV_OVER = GTE_ERROR | (1u << 17);
constexpr uint32_t MAC0_POS = GTE_ERROR | (1u << 16);
constexpr uint32_t MAC0_NEG = GTE_ERROR | (1u << 15);
constexpr uint32_t SX_SAT = GTE_ERROR | (1u << 14);
constexpr uint32_t SY_SAT = GTE_ERROR | (1u << 13);
constexpr uint32_t IR0_SAT = 1u << 12;
constexpr uint32_t ERROR_BITS = 0x7f87e000u;
}  // namespace Flag

// ============================================================================
// Register access
// ============================================================================

inline PAIR* dataRegs() { return g_emulator->m_cpu->m_regs.CP2D.p; }
inline PAIR* ctrlRegs() { return g_emulator->m_cpu->m_regs.CP2C.p; }

// Vertex vectors: compile-time v selection
template <int v>
inline int16_t vertexX() {
    if constexpr (v < 3)
        return dataRegs()[v * 2].sw.l;
    else
        return dataRegs()[9].sw.l;
}
template <int v>
inline int16_t vertexY() {
    if constexpr (v < 3)
        return dataRegs()[v * 2].sw.h;
    else
        return dataRegs()[10].sw.l;
}
template <int v>
inline int16_t vertexZ() {
    if constexpr (v < 3)
        return dataRegs()[v * 2 + 1].sw.l;
    else
        return dataRegs()[11].sw.l;
}

// RGBC
inline uint8_t& rgbR() { return dataRegs()[6].b.l; }
inline uint8_t& rgbG() { return dataRegs()[6].b.h; }
inline uint8_t& rgbB() { return dataRegs()[6].b.h2; }
inline uint8_t& rgbCode() { return dataRegs()[6].b.h3; }

inline uint16_t& otz() { return dataRegs()[7].w.l; }

inline int16_t& ir0() { return dataRegs()[8].sw.l; }
inline int16_t& ir1() { return dataRegs()[9].sw.l; }
inline int16_t& ir2() { return dataRegs()[10].sw.l; }
inline int16_t& ir3() { return dataRegs()[11].sw.l; }

inline uint32_t& sxy0() { return dataRegs()[12].d; }
inline int16_t& sx0() { return dataRegs()[12].sw.l; }
inline int16_t& sy0() { return dataRegs()[12].sw.h; }
inline uint32_t& sxy1() { return dataRegs()[13].d; }
inline int16_t& sx1() { return dataRegs()[13].sw.l; }
inline int16_t& sy1() { return dataRegs()[13].sw.h; }
inline uint32_t& sxy2() { return dataRegs()[14].d; }
inline int16_t& sx2() { return dataRegs()[14].sw.l; }
inline int16_t& sy2() { return dataRegs()[14].sw.h; }

inline uint16_t& sz0() { return dataRegs()[16].w.l; }
inline uint16_t& sz1() { return dataRegs()[17].w.l; }
inline uint16_t& sz2() { return dataRegs()[18].w.l; }
inline uint16_t& sz3() { return dataRegs()[19].w.l; }

inline uint32_t& rgb0() { return dataRegs()[20].d; }
inline uint8_t& rgb0R() { return dataRegs()[20].b.l; }
inline uint8_t& rgb0G() { return dataRegs()[20].b.h; }
inline uint8_t& rgb0B() { return dataRegs()[20].b.h2; }
inline uint32_t& rgb1() { return dataRegs()[21].d; }
inline uint32_t& rgb2() { return dataRegs()[22].d; }
inline uint8_t& rgb2R() { return dataRegs()[22].b.l; }
inline uint8_t& rgb2G() { return dataRegs()[22].b.h; }
inline uint8_t& rgb2B() { return dataRegs()[22].b.h2; }
inline uint8_t& rgb2Cd() { return dataRegs()[22].b.h3; }

inline int32_t& mac0() { return dataRegs()[24].sd; }
inline int32_t& mac1() { return dataRegs()[25].sd; }
inline int32_t& mac2() { return dataRegs()[26].sd; }
inline int32_t& mac3() { return dataRegs()[27].sd; }

// Control registers - rotation matrix
inline int16_t r11() { return ctrlRegs()[0].sw.l; }
inline int16_t r12() { return ctrlRegs()[0].sw.h; }
inline int16_t r13() { return ctrlRegs()[1].sw.l; }
inline int16_t r21() { return ctrlRegs()[1].sw.h; }
inline int16_t r22() { return ctrlRegs()[2].sw.l; }
inline int16_t r23() { return ctrlRegs()[2].sw.h; }
inline int16_t r31() { return ctrlRegs()[3].sw.l; }
inline int16_t r32() { return ctrlRegs()[3].sw.h; }
inline int16_t r33() { return ctrlRegs()[4].sw.l; }

// Control registers used in 64-bit arithmetic return int64_t to avoid casts at every use site.
// The underlying storage is 32-bit or 16-bit; the widening happens here, once.
inline int64_t trX() { return ctrlRegs()[5].sd; }
inline int64_t trY() { return ctrlRegs()[6].sd; }
inline int64_t trZ() { return ctrlRegs()[7].sd; }
inline int64_t rbk() { return ctrlRegs()[13].sd; }
inline int64_t gbk() { return ctrlRegs()[14].sd; }
inline int64_t bbk() { return ctrlRegs()[15].sd; }
inline int64_t rfc() { return ctrlRegs()[21].sd; }
inline int64_t gfc() { return ctrlRegs()[22].sd; }
inline int64_t bfc() { return ctrlRegs()[23].sd; }
inline int64_t gteOFX() { return ctrlRegs()[24].sd; }
inline int64_t gteOFY() { return ctrlRegs()[25].sd; }
inline int16_t gteH() { return ctrlRegs()[26].sw.l; }  // stays 16-bit for gteDivide signature
inline int64_t gteDQA() { return ctrlRegs()[27].sw.l; }
inline int64_t gteDQB() { return ctrlRegs()[28].sd; }
inline int64_t gteZSF3() { return ctrlRegs()[29].sw.l; }
inline int64_t gteZSF4() { return ctrlRegs()[30].sw.l; }
inline uint32_t& gteFlag() { return ctrlRegs()[31].d; }

// Matrix element access - compile-time (mx, row, col)
template <int mx, int row, int col>
inline int32_t matrixElement() {
    if constexpr (mx < 3) {
        constexpr int linear = row * 3 + col;
        constexpr int regIdx = mx * 8 + linear / 2;
        if constexpr (linear & 1)
            return ctrlRegs()[regIdx].sw.h;
        else
            return ctrlRegs()[regIdx].sw.l;
    } else {
        // Garbage matrix: {-R<<4, R<<4, IR0, R13, R13, R13, R22, R22, R22}
        constexpr int linear = row * 3 + col;
        if constexpr (linear == 0) {
            return (-static_cast<int32_t>(dataRegs()[6].b.l)) << 4;
        } else if constexpr (linear == 1) {
            return static_cast<int32_t>(dataRegs()[6].b.l) << 4;
        } else if constexpr (linear == 2) {
            return ir0();
        } else if constexpr (linear <= 5) {
            return ctrlRegs()[1].sw.l;
        }  // R13
        else {
            return ctrlRegs()[2].sw.l;
        }  // R22
    }
}

// Control vector component - compile-time (cv, component)
template <int cv, int component>
inline int64_t controlVector() {
    if constexpr (cv == 3)
        return 0;
    else
        return ctrlRegs()[cv * 8 + 5 + component].sd;
}

// ============================================================================
// Division
// ============================================================================

// UNR reciprocal table generator for GTE division.
// Formula from hardware: unrTable[i] = max(0, ((0x40000 / (i + 0x100)) + 1) / 2 - 0x101)
struct UNRGenerator {
    static consteval uint8_t calculateValue(size_t i) {
        int val = ((0x40000 / (int)(i + 0x100)) + 1) / 2 - 0x101;
        return static_cast<uint8_t>(val < 0 ? 0 : val);
    }
};

inline constexpr auto unrTable = generateTable<257, UNRGenerator>();

inline uint32_t gteDivide(uint16_t numerator, uint16_t denominator) {
    if (numerator >= denominator * 2) {
        gteFlag() |= Flag::DIV_OVER;
        return 0x1ffff;
    }

    int shift = GTE::countLeadingZeros16(denominator);
    int r1 = (denominator << shift) & 0x7fff;
    int r2 = unrTable[((r1 + 0x40) >> 7)] + 0x101;
    int r3 = ((0x80 - (r2 * (r1 + 0x8000))) >> 8) & 0x1ffff;
    uint32_t reciprocal = ((r2 * r3) + 0x80) >> 8;
    uint32_t result = ((static_cast<uint64_t>(reciprocal) * (numerator << shift)) + 0x8000) >> 16;
    return std::min<uint32_t>(0x1ffff, result);
}

// ============================================================================
// Limiter functions
// ============================================================================

inline int32_t lim(int32_t value, int32_t max, int32_t min, uint32_t flag) {
    if (value > max) {
        gteFlag() |= flag;
        return max;
    }
    if (value < min) {
        gteFlag() |= flag;
        return min;
    }
    return value;
}

template <bool sf>
inline int64_t gteShift(int64_t a) {
    if constexpr (sf)
        return a >> 12;
    else
        return a;
}

template <bool sf>
inline int32_t bounds(int44 value, uint32_t posFlag, uint32_t negFlag) {
    if (value.positiveOverflow()) gteFlag() |= posFlag;
    if (value.negativeOverflow()) gteFlag() |= negFlag;
    return static_cast<int32_t>(gteShift<sf>(value.value()));
}

template <bool sf>
inline int32_t A1(int44 a) {
    return bounds<sf>(a, Flag::MAC1_POS, Flag::MAC1_NEG);
}

template <bool sf>
inline int32_t A2(int44 a) {
    return bounds<sf>(a, Flag::MAC2_POS, Flag::MAC2_NEG);
}

template <bool sf>
inline int32_t A3(int44 a, int64_t& rawOut) {
    rawOut = a.value();
    return bounds<sf>(a, Flag::MAC3_POS, Flag::MAC3_NEG);
}

template <bool sf>
inline int32_t A3(int44 a) {
    return bounds<sf>(a, Flag::MAC3_POS, Flag::MAC3_NEG);
}

inline int64_t F(int64_t a, int64_t& rawOut) {
    rawOut = a;
    if (a > INT64_C(0x7fffffff)) gteFlag() |= Flag::MAC0_POS;
    if (a < INT64_C(-0x80000000)) gteFlag() |= Flag::MAC0_NEG;
    return a;
}

inline int64_t F(int64_t a) {
    if (a > INT64_C(0x7fffffff)) gteFlag() |= Flag::MAC0_POS;
    if (a < INT64_C(-0x80000000)) gteFlag() |= Flag::MAC0_NEG;
    return a;
}

template <bool lm>
inline int32_t limB1(int32_t a) {
    return lim(a, 0x7fff, lm ? 0 : -0x8000, Flag::IR1_SAT);
}
template <bool lm>
inline int32_t limB2(int32_t a) {
    return lim(a, 0x7fff, lm ? 0 : -0x8000, Flag::IR2_SAT);
}
template <bool lm>
inline int32_t limB3(int32_t a) {
    return lim(a, 0x7fff, lm ? 0 : -0x8000, Flag::IR3_SAT);
}

template <bool sf, bool lm>
inline int32_t limB3sf(int64_t rawMac3) {
    int32_t valueSf = static_cast<int32_t>(gteShift<sf>(rawMac3));
    int32_t value12 = static_cast<int32_t>(rawMac3 >> 12);
    constexpr int32_t min = lm ? 0 : -0x8000;
    if (value12 < -0x8000 || value12 > 0x7fff) gteFlag() |= Flag::IR3_SAT;
    return std::clamp<int32_t>(valueSf, min, 0x7fff);
}

inline int32_t limC1(int32_t a) { return lim(a, 0xff, 0, Flag::COLOR_R_SAT); }
inline int32_t limC2(int32_t a) { return lim(a, 0xff, 0, Flag::COLOR_G_SAT); }
inline int32_t limC3(int32_t a) { return lim(a, 0xff, 0, Flag::COLOR_B_SAT); }

template <bool sf>
inline int32_t limD(int64_t a) {
    return lim(static_cast<int32_t>(gteShift<sf>(a)), 0xffff, 0, Flag::SZ_SAT);
}

inline int32_t limG1(int64_t a) {
    if (a > 0x3ff) {
        gteFlag() |= Flag::SX_SAT;
        return 0x3ff;
    }
    if (a < -0x400) {
        gteFlag() |= Flag::SX_SAT;
        return -0x400;
    }
    return static_cast<int32_t>(a);
}

inline int32_t limG2(int64_t a) {
    if (a > 0x3ff) {
        gteFlag() |= Flag::SY_SAT;
        return 0x3ff;
    }
    if (a < -0x400) {
        gteFlag() |= Flag::SY_SAT;
        return -0x400;
    }
    return static_cast<int32_t>(a);
}

inline int32_t limG1ia(int64_t a) { return static_cast<int32_t>(std::clamp<int64_t>(a, -0x4000000, 0x3ffffff)); }
inline int32_t limG2ia(int64_t a) { return static_cast<int32_t>(std::clamp<int64_t>(a, -0x4000000, 0x3ffffff)); }

inline int32_t limH(int64_t rawMac0) {
    int64_t valueSf = rawMac0 >> 12;
    int32_t value12 = static_cast<int32_t>(rawMac0 >> 12);
    if (valueSf < 0 || valueSf > 0x1000) gteFlag() |= Flag::IR0_SAT;
    return std::clamp<int32_t>(value12, 0, 0x1000);
}

// ============================================================================
// FIFO operations
// ============================================================================

inline void pushZ(uint16_t z) {
    sz0() = sz1();
    sz1() = sz2();
    sz2() = sz3();
    sz3() = z;
}

inline void pushColor() {
    rgb0() = rgb1();
    rgb1() = rgb2();
    rgb2Cd() = rgbCode();
    rgb2R() = limC1(mac1() >> 4);
    rgb2G() = limC2(mac2() >> 4);
    rgb2B() = limC3(mac3() >> 4);
}

// ============================================================================
// Pipeline stage: matrix-vector multiply (fully templatized)
// ============================================================================

template <bool sf, bool lm, int mx, int v, int cv>
inline void matrixVectorMultiply(int64_t& rawMac3) {
    if constexpr (cv == 2) {
        // FC bug path: columns 1-2 first, then column 0 for FLAG only
        mac1() = A1<sf>(int44(matrixElement<mx, 0, 1>() * vertexY<v>()) + matrixElement<mx, 0, 2>() * vertexZ<v>());
        mac2() = A2<sf>(int44(matrixElement<mx, 1, 1>() * vertexY<v>()) + matrixElement<mx, 1, 2>() * vertexZ<v>());
        mac3() =
            A3<sf>(int44(matrixElement<mx, 2, 1>() * vertexY<v>()) + matrixElement<mx, 2, 2>() * vertexZ<v>(), rawMac3);
        // Column 0: FLAG side effects only, results discarded
        limB1<false>(A1<sf>(int44(controlVector<cv, 0>() << 12) + matrixElement<mx, 0, 0>() * vertexX<v>()));
        limB2<false>(A2<sf>(int44(controlVector<cv, 1>() << 12) + matrixElement<mx, 1, 0>() * vertexX<v>()));
        limB3<false>(A3<sf>(int44(controlVector<cv, 2>() << 12) + matrixElement<mx, 2, 0>() * vertexX<v>()));
    } else {
        mac1() = A1<sf>(int44(controlVector<cv, 0>() << 12) + matrixElement<mx, 0, 0>() * vertexX<v>() +
                        matrixElement<mx, 0, 1>() * vertexY<v>() + matrixElement<mx, 0, 2>() * vertexZ<v>());
        mac2() = A2<sf>(int44(controlVector<cv, 1>() << 12) + matrixElement<mx, 1, 0>() * vertexX<v>() +
                        matrixElement<mx, 1, 1>() * vertexY<v>() + matrixElement<mx, 1, 2>() * vertexZ<v>());
        mac3() = A3<sf>(int44(controlVector<cv, 2>() << 12) + matrixElement<mx, 2, 0>() * vertexX<v>() +
                            matrixElement<mx, 2, 1>() * vertexY<v>() + matrixElement<mx, 2, 2>() * vertexZ<v>(),
                        rawMac3);
    }
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
}

template <bool sf, bool lm, int mx, int v, int cv>
inline void matrixVectorMultiply() {
    int64_t unused;
    matrixVectorMultiply<sf, lm, mx, v, cv>(unused);
}

// ============================================================================
// Pipeline stage: light transform - L * V(v) -> MAC/IR
// ============================================================================

template <bool sf, bool lm, int v>
inline void lightTransform() {
    matrixVectorMultiply<sf, lm, 1, v, 3>();
}

// ============================================================================
// Pipeline stage: color matrix - BK + C * IR -> MAC/IR
// ============================================================================

template <bool sf, bool lm>
inline void colorMatrix() {
    matrixVectorMultiply<sf, lm, 2, 3, 1>();
}

// ============================================================================
// Pipeline stage: depth cue interpolation
// ============================================================================

template <bool sf, bool lm>
inline void depthCue(int64_t inR, int64_t inG, int64_t inB) {
    mac1() = A1<sf>(inR + ir0() * limB1<false>(A1<sf>((rfc() << 12) - inR)));
    mac2() = A2<sf>(inG + ir0() * limB2<false>(A2<sf>((gfc() << 12) - inG)));
    int64_t rawMac3;
    mac3() = A3<sf>(inB + ir0() * limB3<false>(A3<sf>((bfc() << 12) - inB)), rawMac3);
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
}

template <bool sf, bool lm>
inline void depthCueColor() {
    depthCue<sf, lm>((int64_t)(rgbR() << 4) * ir1(), (int64_t)(rgbG() << 4) * ir2(), (int64_t)(rgbB() << 4) * ir3());
}

// ============================================================================
// Pipeline stage: color apply - RGBC * IR -> MAC/IR
// ============================================================================

template <bool sf, bool lm>
inline void colorApply() {
    mac1() = A1<sf>((int64_t)(rgbR() << 4) * ir1());
    mac2() = A2<sf>((int64_t)(rgbG() << 4) * ir2());
    mac3() = A3<sf>((int64_t)(rgbB() << 4) * ir3());
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
}

// ============================================================================
// Dispatch helpers
// ============================================================================

inline unsigned sfLmIndex(uint32_t op) { return ((op >> 18) & 2) | ((op >> 10) & 1); }

// Generate a 256-entry dispatch table for MVMVA (sf * lm * mx * v * cv).
// Index layout: [sf:1][lm:1][mx:2][v:2][cv:2]
template <typename Fn, template <bool, bool, int, int, int> class Impl, size_t... Is>
constexpr auto makeMvmvaTable(std::index_sequence<Is...>) {
    return std::array<Fn, sizeof...(Is)>{
        Impl<bool(Is >> 7), bool((Is >> 6) & 1), int((Is >> 4) & 3), int((Is >> 2) & 3), int(Is & 3)>::fn...};
}

}  // namespace GTEImpl
}  // namespace PCSX
