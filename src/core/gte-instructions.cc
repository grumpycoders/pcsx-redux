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

// GTE instruction implementations and public dispatch methods.
//
// Each instruction is implemented as a template parameterized on sf (shift
// factor) and lm (limit mode). The public methods decode these bits from
// the instruction encoding and dispatch to the right instantiation.
//
// MVMVA is further templatized on mx, v, and cv for full compile-time
// elimination of the matrix/vector selection branches.

#include "core/gte.h"
#include "core/gte-internal.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"

using namespace PCSX::GTEImpl;

// ============================================================================
// Template instruction implementations
// ============================================================================

// RTPS core: perspective transform for vertex v.
// When last=true, computes the depth queue interpolation at the end.
template <bool sf, bool lm, int v>
static void rtps(bool last) {
    mac1() = A1<sf>(int44(trX() << 12) +
                    r11() * vertexX<v>() + r12() * vertexY<v>() + r13() * vertexZ<v>());
    mac2() = A2<sf>(int44(trY() << 12) +
                    r21() * vertexX<v>() + r22() * vertexY<v>() + r23() * vertexZ<v>());
    int64_t rawMac3;
    mac3() = A3<sf>(int44(trZ() << 12) +
                    r31() * vertexX<v>() + r32() * vertexY<v>() + r33() * vertexZ<v>(), rawMac3);

    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3sf<sf, lm>(rawMac3);

    pushZ(limD<true>(rawMac3));

    int32_t hOverSz3 = gteDivide(gteH(), sz3());

    sxy0() = sxy1();
    sxy1() = sxy2();

    double widescreenFactor = PCSX::g_emulator->config().Widescreen ? 0.75 : 1.0;
    // ir1()*hOverSz3 can exceed int32_t (hOverSz3 is up to 0x1FFFF), so widen ir first
    sx2() = limG1(F(gteOFX() + (int64_t)ir1() * hOverSz3 * widescreenFactor) >> 16);
    sy2() = limG2(F(gteOFY() + (int64_t)ir2() * hOverSz3) >> 16);

    PGXP_pushSXYZ2s(limG1ia(gteOFX() + (int64_t)(ir1() * hOverSz3) * widescreenFactor),
                     limG2ia(gteOFY() + (int64_t)(ir2() * hOverSz3)),
                     std::max((int)sz3(), gteH() / 2), sxy2());

    if (last) {
        int64_t rawMac0;
        mac0() = F(gteDQB() + gteDQA() * hOverSz3, rawMac0);
        ir0() = limH(rawMac0);
    }
}

// OP: outer product using rotation matrix diagonal
template <bool sf, bool lm>
void PCSX::GTE::op(uint32_t op) {
    gteFlag() = 0;
    mac1() = A1<sf>(r22() * ir3() - r33() * ir2());
    mac2() = A2<sf>(r33() * ir1() - r11() * ir3());
    mac3() = A3<sf>(r11() * ir2() - r22() * ir1());
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
}

template <bool sf, bool lm>
void PCSX::GTE::dpcs(uint32_t op) {
    gteFlag() = 0;
    depthCue<sf, lm>(rgbR() << 16, rgbG() << 16, rgbB() << 16);
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::intpl(uint32_t op) {
    gteFlag() = 0;
    depthCue<sf, lm>(ir1() << 12, ir2() << 12, ir3() << 12);
    pushColor();
}

// MVMVA: fully templatized wrapper for dispatch table
template <bool sf, bool lm, int mx, int v, int cv>
static void mvmvaImpl() {
    gteFlag() = 0;
    matrixVectorMultiply<sf, lm, mx, v, cv>();
}

// NCDS core: used by NCDS (v=0) and NCDT (v=0,1,2)
template <bool sf, bool lm, int v>
static void ncdsCore() {
    lightTransform<sf, lm, v>();
    colorMatrix<sf, lm>();
    depthCueColor<sf, lm>();
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::cdp(uint32_t op) {
    gteFlag() = 0;
    colorMatrix<sf, lm>();
    depthCueColor<sf, lm>();
    pushColor();
}

// NCCS core: used by NCCS (v=0) and NCCT (v=0,1,2)
template <bool sf, bool lm, int v>
static void nccsCore() {
    lightTransform<sf, lm, v>();
    colorMatrix<sf, lm>();
    colorApply<sf, lm>();
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::cc(uint32_t op) {
    gteFlag() = 0;
    colorMatrix<sf, lm>();
    colorApply<sf, lm>();
    pushColor();
}

// NCS core: used by NCS (v=0) and NCT (v=0,1,2)
template <bool sf, bool lm, int v>
static void ncsCore() {
    lightTransform<sf, lm, v>();
    colorMatrix<sf, lm>();
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::sqr(uint32_t op) {
    gteFlag() = 0;
    mac1() = A1<sf>(ir1() * ir1());
    mac2() = A2<sf>(ir2() * ir2());
    mac3() = A3<sf>(ir3() * ir3());
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
}

template <bool sf, bool lm>
void PCSX::GTE::dcpl(uint32_t op) {
    gteFlag() = 0;
    depthCueColor<sf, lm>();
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::dpct(uint32_t op) {
    gteFlag() = 0;
    for (int v = 0; v < 3; v++) {
        depthCue<sf, lm>(rgb0R() << 16, rgb0G() << 16, rgb0B() << 16);
        pushColor();
    }
}

template <bool sf, bool lm>
void PCSX::GTE::gpf(uint32_t op) {
    gteFlag() = 0;
    mac1() = A1<sf>(ir0() * ir1());
    mac2() = A2<sf>(ir0() * ir2());
    mac3() = A3<sf>(ir0() * ir3());
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
    pushColor();
}

template <bool sf, bool lm>
void PCSX::GTE::gpl(uint32_t op) {
    gteFlag() = 0;
    int64_t shiftedMac1, shiftedMac2, shiftedMac3;
    if constexpr (sf) {
        shiftedMac1 = (int64_t)mac1() << 12;  // <<12 on int32_t overflows
        shiftedMac2 = (int64_t)mac2() << 12;
        shiftedMac3 = (int64_t)mac3() << 12;
    } else {
        shiftedMac1 = mac1();
        shiftedMac2 = mac2();
        shiftedMac3 = mac3();
    }
    mac1() = A1<sf>(shiftedMac1 + ir0() * ir1());
    mac2() = A2<sf>(shiftedMac2 + ir0() * ir2());
    mac3() = A3<sf>(shiftedMac3 + ir0() * ir3());
    ir1() = limB1<lm>(mac1());
    ir2() = limB2<lm>(mac2());
    ir3() = limB3<lm>(mac3());
    pushColor();
}

// ============================================================================
// MVMVA dispatch table (256 entries: sf * lm * mx * v * cv)
// ============================================================================

namespace {

template <bool sf, bool lm, int mx, int v, int cv>
struct MvmvaEntry {
    static void fn() { mvmvaImpl<sf, lm, mx, v, cv>(); }
};

using MvmvaFn = void (*)();

constexpr auto mvmvaTable =
    PCSX::GTEImpl::makeMvmvaTable<MvmvaFn, MvmvaEntry>(std::make_index_sequence<256>{});

}  // anonymous namespace

// ============================================================================
// Public dispatch methods
// ============================================================================

#define GTE_DISPATCH_SF_LM(method, ...)                                    \
    do {                                                                    \
        uint32_t _op = code & 0x1ffffff;                                    \
        switch (sfLmIndex(_op)) {                                           \
            case 0: method<false, false>(_op, ##__VA_ARGS__); break;        \
            case 1: method<false, true>(_op, ##__VA_ARGS__); break;         \
            case 2: method<true, false>(_op, ##__VA_ARGS__); break;         \
            case 3: method<true, true>(_op, ##__VA_ARGS__); break;          \
        }                                                                   \
    } while (0)

void PCSX::GTE::RTPS(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: rtps<false, false, 0>(true); break;
        case 1: rtps<false, true, 0>(true); break;
        case 2: rtps<true, false, 0>(true); break;
        case 3: rtps<true, true, 0>(true); break;
    }
}

void PCSX::GTE::RTPT(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: rtps<false, false, 0>(false); rtps<false, false, 1>(false); rtps<false, false, 2>(true); break;
        case 1: rtps<false, true, 0>(false); rtps<false, true, 1>(false); rtps<false, true, 2>(true); break;
        case 2: rtps<true, false, 0>(false); rtps<true, false, 1>(false); rtps<true, false, 2>(true); break;
        case 3: rtps<true, true, 0>(false); rtps<true, true, 1>(false); rtps<true, true, 2>(true); break;
    }
}

void PCSX::GTE::NCLIP(uint32_t code) {
    gteFlag() = 0;
    if (PGXP_NLCIP_valid(sxy0(), sxy1(), sxy2()))
        mac0() = F(PGXP_NCLIP());
    else
        mac0() = F((int64_t)sx0() * sy1() + sx1() * sy2() + sx2() * sy0() -
                    sx0() * sy2() - sx1() * sy0() - sx2() * sy1());
}

void PCSX::GTE::OP(uint32_t code) { GTE_DISPATCH_SF_LM(op); }
void PCSX::GTE::DPCS(uint32_t code) { GTE_DISPATCH_SF_LM(dpcs); }
void PCSX::GTE::INTPL(uint32_t code) { GTE_DISPATCH_SF_LM(intpl); }

void PCSX::GTE::MVMVA(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    unsigned sf = (_op >> 19) & 1;
    unsigned lm = (_op >> 10) & 1;
    unsigned mx = (_op >> 17) & 3;
    unsigned v = (_op >> 15) & 3;
    unsigned cv = (_op >> 13) & 3;
    unsigned idx = (sf << 7) | (lm << 6) | (mx << 4) | (v << 2) | cv;
    mvmvaTable[idx]();
}

void PCSX::GTE::NCDS(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: ncdsCore<false, false, 0>(); break;
        case 1: ncdsCore<false, true, 0>(); break;
        case 2: ncdsCore<true, false, 0>(); break;
        case 3: ncdsCore<true, true, 0>(); break;
    }
}

void PCSX::GTE::CDP(uint32_t code) { GTE_DISPATCH_SF_LM(cdp); }

void PCSX::GTE::NCDT(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: ncdsCore<false, false, 0>(); ncdsCore<false, false, 1>(); ncdsCore<false, false, 2>(); break;
        case 1: ncdsCore<false, true, 0>(); ncdsCore<false, true, 1>(); ncdsCore<false, true, 2>(); break;
        case 2: ncdsCore<true, false, 0>(); ncdsCore<true, false, 1>(); ncdsCore<true, false, 2>(); break;
        case 3: ncdsCore<true, true, 0>(); ncdsCore<true, true, 1>(); ncdsCore<true, true, 2>(); break;
    }
}

void PCSX::GTE::NCCS(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: nccsCore<false, false, 0>(); break;
        case 1: nccsCore<false, true, 0>(); break;
        case 2: nccsCore<true, false, 0>(); break;
        case 3: nccsCore<true, true, 0>(); break;
    }
}

void PCSX::GTE::CC(uint32_t code) { GTE_DISPATCH_SF_LM(cc); }

void PCSX::GTE::NCS(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: ncsCore<false, false, 0>(); break;
        case 1: ncsCore<false, true, 0>(); break;
        case 2: ncsCore<true, false, 0>(); break;
        case 3: ncsCore<true, true, 0>(); break;
    }
}

void PCSX::GTE::NCT(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: ncsCore<false, false, 0>(); ncsCore<false, false, 1>(); ncsCore<false, false, 2>(); break;
        case 1: ncsCore<false, true, 0>(); ncsCore<false, true, 1>(); ncsCore<false, true, 2>(); break;
        case 2: ncsCore<true, false, 0>(); ncsCore<true, false, 1>(); ncsCore<true, false, 2>(); break;
        case 3: ncsCore<true, true, 0>(); ncsCore<true, true, 1>(); ncsCore<true, true, 2>(); break;
    }
}

void PCSX::GTE::SQR(uint32_t code) { GTE_DISPATCH_SF_LM(sqr); }
void PCSX::GTE::DCPL(uint32_t code) { GTE_DISPATCH_SF_LM(dcpl); }
void PCSX::GTE::DPCT(uint32_t code) { GTE_DISPATCH_SF_LM(dpct); }

void PCSX::GTE::AVSZ3(uint32_t code) {
    gteFlag() = 0;
    int64_t rawMac0;
    mac0() = F(gteZSF3() * sz1() + gteZSF3() * sz2() + gteZSF3() * sz3(), rawMac0);
    otz() = limD<true>(rawMac0);
}

void PCSX::GTE::AVSZ4(uint32_t code) {
    gteFlag() = 0;
    int64_t rawMac0;
    mac0() = F(gteZSF4() * sz0() + gteZSF4() * sz1() + gteZSF4() * sz2() + gteZSF4() * sz3(), rawMac0);
    otz() = limD<true>(rawMac0);
}

void PCSX::GTE::GPF(uint32_t code) { GTE_DISPATCH_SF_LM(gpf); }
void PCSX::GTE::GPL(uint32_t code) { GTE_DISPATCH_SF_LM(gpl); }

void PCSX::GTE::NCCT(uint32_t code) {
    uint32_t _op = code & 0x1ffffff;
    gteFlag() = 0;
    switch (sfLmIndex(_op)) {
        case 0: nccsCore<false, false, 0>(); nccsCore<false, false, 1>(); nccsCore<false, false, 2>(); break;
        case 1: nccsCore<false, true, 0>(); nccsCore<false, true, 1>(); nccsCore<false, true, 2>(); break;
        case 2: nccsCore<true, false, 0>(); nccsCore<true, false, 1>(); nccsCore<true, false, 2>(); break;
        case 3: nccsCore<true, true, 0>(); nccsCore<true, true, 1>(); nccsCore<true, true, 2>(); break;
    }
}

#undef GTE_DISPATCH_SF_LM
