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

#include "psyqo/bezier.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/matrix.hh"
#include "psyqo/vector.hh"

/*
 * GteMath - the SoftMath operations that the GTE can do in hardware.
 *
 * These mirror SoftMath's signatures and argument conventions exactly, so they
 * are drop-in. Where SoftMath has a quirk, this keeps the quirk rather than
 * fixing it, because a caller swapping one for the other should not have to
 * re-derive anything. multiplyMatrix33 in particular computes out = m2 * m1,
 * matching SoftMath.
 *
 * WHY THESE ARE FREE FUNCTIONS AND NOT A SCOPED, REGISTER-OWNING OBJECT.
 * Measured on hardware (src/mips/tests/gte-math-bench), cycles per element,
 * SCPH-5501, caller at -O2, "cold" meaning the matrix upload is paid INSIDE the
 * call, once per element:
 *
 *     operation           soft    cold    hot    cold speedup
 *     matrixVecMul3     271.66  126.58  47.63       2.15x
 *     matrixVecMul3xy   170.70  123.60  45.71       1.38x
 *     crossProductVec3  187.76   73.32  46.56       2.56x
 *     project           709.41  140.03  52.58       5.07x
 *     multiplyMatrix33 1144.06  209.38 127.63       5.46x
 *
 * There is no crossover: the GTE wins at a batch of one for everything
 * measured, so the simple form never loses and needs no caveats. Hoisting the
 * setup is still worth about 2.7x on top, which is what the batching helpers
 * further down are for - but that is an optimisation, not the architecture.
 *
 * The reason the software side is so expensive is not instruction count. On the
 * R3000A `mult` and `divu` are multi-cycle and `mflo` interlocks, so every
 * FixedPoint multiply stalls. Three independent operations above work out at
 * 28-31 cycles per fixed-point multiply. `project` is dominated by a single
 * `divu`: 681 of its 709 cycles are the one divide.
 *
 * INLINING. psyqo builds at -Os, where GCC does NOT inline the GTE register
 * accessors - it emits `jal` into writeSafe/read, and that measured up to +67%
 * on the cold numbers above. Everything here is therefore in the header and
 * marked always_inline. Do not move these to a .cpp built at -Os.
 *
 * REGISTER CLOBBERS. Each function documents what it destroys. This is the real
 * API surface: a caller who has a rotation matrix loaded for projection cannot
 * casually call crossProductVec3 in the middle of a render loop, because the
 * GTE's cross product uses the rotation matrix DIAGONAL as one of its operands.
 * That one is a landmine, so it is spelled out on every function rather than
 * once at the top.
 *
 * RESTORING. Prefer re-uploading from the copy you still have in RAM over
 * reading registers back. A Matrix33 is five ctc2; reading it back is nine
 * mfc2 plus hazard nops. "Save and restore" is the expensive direction here.
 */

namespace psyqo {

namespace GteMath {

#define PSYQO_GTE_MATH_INLINE [[gnu::always_inline]] static inline

/**
 * @brief Multiplies a vector by a matrix.
 *
 * @details Drop-in for SoftMath::matrixVecMul3. 2.15x on hardware even paying
 * the matrix upload here.
 *
 * CLOBBERS: the rotation matrix (RT), V0, IR1-3, MAC1-3.
 */
PSYQO_GTE_MATH_INLINE void matrixVecMul3(const Matrix33 &m, const Vec3 &v, Vec3 *out) {
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(m);
    GTE::writeSafe<GTE::PseudoRegister::V0>(v);
    GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0>();
    *out = Vec3(GTE::readSafe<GTE::PseudoRegister::SV>());
}

/**
 * @brief Multiplies a vector by a matrix, keeping only x and y.
 *
 * CLOBBERS: the rotation matrix (RT), V0, IR1-3, MAC1-3.
 */
PSYQO_GTE_MATH_INLINE void matrixVecMul3xy(const Matrix33 &m, const Vec3 &v, Vec2 *out) {
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(m);
    GTE::writeSafe<GTE::PseudoRegister::V0>(v);
    GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0>();
    Vec3 r = Vec3(GTE::readSafe<GTE::PseudoRegister::SV>());
    out->x = r.x;
    out->y = r.y;
}

/**
 * @brief Multiplies a vector by a matrix, keeping only z.
 *
 * CLOBBERS: the rotation matrix (RT), V0, IR1-3, MAC1-3.
 */
PSYQO_GTE_MATH_INLINE FixedPoint<> matrixVecMul3z(const Matrix33 &m, const Vec3 &v) {
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(m);
    GTE::writeSafe<GTE::PseudoRegister::V0>(v);
    GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0>();
    return Vec3(GTE::readSafe<GTE::PseudoRegister::SV>()).z;
}

/**
 * @brief Builds a matrix from three column vectors.
 *
 * @details Matrix33 stores ROWS. Several GTE formulations want the matrix built
 * from columns - a weighted sum of three vectors is one MVMVA only if those
 * vectors are the columns - so this scatters each one across the three rows.
 * Getting it backwards produces plausible-looking garbage, which is why it is a
 * named function rather than an open-coded initialiser at each site.
 */
PSYQO_GTE_MATH_INLINE Matrix33 fromColumns(const Vec3 &c0, const Vec3 &c1, const Vec3 &c2) {
    return {{
        {c0.x, c1.x, c2.x},
        {c0.y, c1.y, c2.y},
        {c0.z, c1.z, c2.z},
    }};
}

/**
 * @brief Multiplies two matrices.
 *
 * @details out = m2 * m1, matching SoftMath::multiplyMatrix33's convention.
 * Column j of the product is m2 applied to column j of m1, so this is three
 * MVMVA against 27 fixed-point multiplies: 5.46x on hardware.
 *
 * Aliasing is fine: the result is accumulated before anything is written back,
 * so `out` may be `&m1` or `&m2`.
 *
 * CLOBBERS: the rotation matrix (RT), V0, IR1-3, MAC1-3.
 */
PSYQO_GTE_MATH_INLINE void multiplyMatrix33(const Matrix33 &m1, const Matrix33 &m2, Matrix33 *out) {
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(m2);
    const Vec3 cols[3] = {
        {m1.vs[0].x, m1.vs[1].x, m1.vs[2].x},
        {m1.vs[0].y, m1.vs[1].y, m1.vs[2].y},
        {m1.vs[0].z, m1.vs[1].z, m1.vs[2].z},
    };
    Vec3 res[3];
    for (unsigned j = 0; j < 3; j++) {
        GTE::writeSafe<GTE::PseudoRegister::V0>(cols[j]);
        GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0>();
        res[j] = Vec3(GTE::readSafe<GTE::PseudoRegister::SV>());
    }
    out->vs[0] = {res[0].x, res[1].x, res[2].x};
    out->vs[1] = {res[0].y, res[1].y, res[2].y};
    out->vs[2] = {res[0].z, res[1].z, res[2].z};
}

/**
 * @brief Cross product of two vectors.
 *
 * @details 2.56x on hardware, but read the clobber list before reaching for it.
 *
 * CLOBBERS: R11, R22 and R33 - the ROTATION MATRIX DIAGONAL - plus IR1-3 and
 * MAC1-3. The GTE's cross product takes its first operand from those three
 * matrix elements rather than from a vector register, so calling this destroys
 * a loaded rotation matrix. That makes it unsafe inside a projection loop
 * unless you reload RT afterwards. It is free at load time, when nothing owns
 * RT yet.
 */
PSYQO_GTE_MATH_INLINE void crossProductVec3(const Vec3 &v1, const Vec3 &v2, Vec3 *out) {
    Vec3 a = v1;
    Vec3 b = v2;
    GTE::write<GTE::Register::R11R12, GTE::Unsafe>(a.x.raw());
    GTE::write<GTE::Register::R22R23, GTE::Unsafe>(a.y.raw());
    GTE::write<GTE::Register::R33, GTE::Unsafe>(a.z.raw());
    GTE::write<GTE::Register::IR1, GTE::Unsafe>(reinterpret_cast<uint32_t *>(&b.x));
    GTE::write<GTE::Register::IR2, GTE::Unsafe>(reinterpret_cast<uint32_t *>(&b.y));
    GTE::write<GTE::Register::IR3, GTE::Safe>(reinterpret_cast<uint32_t *>(&b.z));
    GTE::Kernels::cp();
    GTE::read<GTE::PseudoRegister::LV>(*out);
}

/**
 * @brief The seed for an inverse square root, from the GTE's leading-bit count.
 *
 * @details The seed wants HALF the exponent, since the target is 1/sqrt(x) and
 * not 1/x. With lzcr = 31 - floor(log2(x.raw())), that is (5 + lzcr) / 2 in
 * 20.12. Shifting by the whole count is a seed for the wrong function: it is
 * correct only where x == 0.0625 and diverges either side, and because
 * SoftMath::inverseSquareRoot is four Newton steps with no convergence check, a
 * seed outside the basin explodes rather than degrading. Swept over all 4096
 * representable values below 1.0, the halved exponent has a worst relative
 * error of 0.48% and no failures; the unhalved one breaks 199 of them.
 *
 * CLOBBERS: LZCS and LZCR only. Safe to call with a matrix loaded.
 *
 * NOTE: LZCS/LZCR do not interlock the way the cop2 commands do - they are the
 * one corner of the GTE where the hardware will not stall for you - so the
 * write must be Safe.
 */
PSYQO_GTE_MATH_INLINE FixedPoint<> inverseSquareRootSeed(FixedPoint<> x) {
    GTE::write<GTE::Register::LZCS, GTE::Safe>(x.raw());
    int32_t shift = (5 + int32_t(GTE::readRaw<GTE::Register::LZCR>())) / 2;
    return FixedPoint<>(int32_t(1) << shift, FixedPoint<>::RAW);
}

/**
 * @brief Normalises a vector in place.
 *
 * @details Drop-in for SoftMath::normalizeVec3, which reaches 1/sqrt through
 * squareRoot's shift-subtract loop at about 3588 cycles a vector. This keeps
 * the squared length on the CPU - three multiplies - and takes only the seed
 * from the GTE, then uses the existing Newton refinement. Measured against the
 * exact version over 800 vectors, worst component deviation is 10 raw out of
 * 4096, i.e. 0.24%.
 *
 * A zero-length vector is left as (0, 0, 1) rather than dividing by zero:
 * SoftMath::squareRoot returns 0 for x.raw() <= 1 and normalizeVec3 then
 * divides by it.
 *
 * CLOBBERS: LZCS and LZCR only.
 */
void normalizeVec3(Vec3 *v);

/**
 * @brief Normalises a vector in place, without the exact square root.
 *
 * @details Same as normalizeVec3 here. SoftMath draws a distinction between an
 * exact normalize and a fast one; on this path there is no reason for two, and
 * the "fast" one in SoftMath seeds inverseSquareRoot with x * 2, which moves
 * the wrong way as the vector shrinks.
 *
 * CLOBBERS: LZCS and LZCR only.
 */
PSYQO_GTE_MATH_INLINE void fastNormalizeVec3(Vec3 *v) { normalizeVec3(v); }

/**
 * @brief Evaluates a cubic Bezier at t.
 *
 * @details A cubic Bezier is a weighted sum of four control points, and MVMVA
 * computes Mx * Vx + Tx. Load three control points as the matrix COLUMNS and
 * the Bernstein weights as the vector, and the fourth term rides in the
 * translation register. One GTE op plus three multiplies, against twelve
 * multiplies in software.
 *
 * This is the operation that justifies the header on its own: a curve sampled
 * once per frame is how you get smooth camera motion along a 3D path, and that
 * is a realtime cost rather than a load-time one.
 *
 * Verified against psyqo::Bezier::cubic: worst component deviation 3 raw out of
 * 4096.
 *
 * CLOBBERS: the rotation matrix (RT), the translation vector (TR), V0, IR1-3,
 * MAC1-3.
 */
PSYQO_GTE_MATH_INLINE Vec3 cubic(const Vec3 &a, const Vec3 &b, const Vec3 &c, const Vec3 &d, FixedPoint<> t) {
    using namespace psyqo::fixed_point_literals;
    FixedPoint<> mt = 1.0_fp - t;
    FixedPoint<> mt2 = mt * mt;
    FixedPoint<> t2 = t * t;
    FixedPoint<> f4 = t2 * t;
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(fromColumns(a, b, c));
    GTE::writeUnsafe<GTE::PseudoRegister::Translation>(Vec3{d.x * f4, d.y * f4, d.z * f4});
    GTE::writeSafe<GTE::PseudoRegister::V0>(Vec3{mt2 * mt, mt2 * t * 3, mt * t2 * 3});
    GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0, GTE::Kernels::TV::TR>();
    return Vec3(GTE::readSafe<GTE::PseudoRegister::SV>());
}

/**
 * @brief Evaluates the derivative of a cubic Bezier at t.
 *
 * @details The derivative is a quadratic Bezier over the differences of
 * consecutive control points, so it is only THREE terms and needs no
 * translation vector at all - one MVMVA and nothing else.
 *
 * The factor of three that belongs in a true derivative is dropped. The usual
 * consumer is a tangent that gets crossed and normalised, where only the
 * direction survives; scale it yourself if you need the real magnitude.
 *
 * CLOBBERS: the rotation matrix (RT), V0, IR1-3, MAC1-3. Not TR.
 */
PSYQO_GTE_MATH_INLINE Vec3 cubicDerivative(const Vec3 &a, const Vec3 &b, const Vec3 &c, const Vec3 &d,
                                           FixedPoint<> t) {
    using namespace psyqo::fixed_point_literals;
    FixedPoint<> mt = 1.0_fp - t;
    Vec3 ab = {b.x - a.x, b.y - a.y, b.z - a.z};
    Vec3 bc = {c.x - b.x, c.y - b.y, c.z - b.z};
    Vec3 cd = {d.x - c.x, d.y - c.y, d.z - c.z};
    GTE::writeUnsafe<GTE::PseudoRegister::Rotation>(fromColumns(ab, bc, cd));
    GTE::writeSafe<GTE::PseudoRegister::V0>(Vec3{mt * mt, mt * t * 2, t * t});
    GTE::Kernels::mvmva<GTE::Kernels::MX::RT, GTE::Kernels::MV::V0>();
    return Vec3(GTE::readSafe<GTE::PseudoRegister::SV>());
}

#undef PSYQO_GTE_MATH_INLINE

}  // namespace GteMath

}  // namespace psyqo
