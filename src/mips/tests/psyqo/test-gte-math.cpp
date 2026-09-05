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

#include "psyqo/gte-math.hh"

#include "psyqo/matrix.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/vector.hh"
#include "snitch_all.hpp"

/*
 * GteMath is meant to be a drop-in for SoftMath, so the question is not whether
 * it produces a plausible number but whether it produces the SAME number.
 * Everything here runs both implementations over a spread of inputs and bounds
 * the difference, in raw 20.12 units where 4096 is 1.0.
 *
 * The tolerances are not round numbers chosen to make this pass. The GTE works
 * in 1.3.12 through 16-bit IR registers where SoftMath carries 32 bits
 * throughout, so exact agreement is not available and a tolerance of zero would
 * only mean the test was lying.
 */

using namespace psyqo;
using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

namespace {

constexpr int32_t kVecTolerance = 16;
constexpr int32_t kMatTolerance = 8;
constexpr int32_t kNormalTolerance = 24;

Trig<> g_trig;

int32_t absDiff(FixedPoint<> a, FixedPoint<> b) {
    int32_t d = a.raw() - b.raw();
    return d < 0 ? -d : d;
}

int32_t worstVec(const Vec3& a, const Vec3& b) {
    int32_t x = absDiff(a.x, b.x);
    int32_t y = absDiff(a.y, b.y);
    int32_t z = absDiff(a.z, b.z);
    int32_t m = x > y ? x : y;
    return z > m ? z : m;
}

int32_t worstMat(const Matrix33& a, const Matrix33& b) {
    int32_t m = 0;
    for (unsigned r = 0; r < 3; r++) {
        int32_t w = worstVec(a.vs[r], b.vs[r]);
        if (w > m) m = w;
    }
    return m;
}

// Axis-aligned, diagonal, large, negative, and some small ones - small is where
// an inverse square root seed goes wrong.
//
// These stay above about |v| = 0.1 because the SoftMath side cannot go lower:
// SoftMath::normalizeVec3 divides by squareRoot(s), squareRoot returns 0 for a
// small enough argument, and the result is a divide by zero that traps rather
// than returning anything. GteMath guards it; the reference does not, so a
// genuinely tiny vector here would crash the oracle and not the subject. The
// degenerate case is covered on its own below, against GteMath alone.
const Vec3 c_vectors[] = {
    {1.0_fp, 0.0_fp, 0.0_fp},    {0.0_fp, 1.0_fp, 0.0_fp},      {0.0_fp, 0.0_fp, 1.0_fp},
    {1.0_fp, 1.0_fp, 1.0_fp},    {-1.0_fp, 0.5_fp, -0.25_fp},   {3.5_fp, -2.0_fp, 1.25_fp},
    {0.25_fp, 0.25_fp, 0.25_fp}, {0.15_fp, -0.2_fp, 0.1_fp},    {2.0_fp, 0.0_fp, -3.0_fp},
    {-0.7_fp, -0.7_fp, 0.14_fp}, {0.125_fp, 0.25_fp, 0.5_fp},   {-3.4_fp, 3.4_fp, 0.0_fp},
};
constexpr unsigned c_vectorCount = sizeof(c_vectors) / sizeof(c_vectors[0]);

Matrix33 someMatrix(unsigned i) {
    Angle a = 0.13_pi * int32_t(i + 1);
    auto axis = (i % 3 == 0) ? SoftMath::Axis::X : (i % 3 == 1) ? SoftMath::Axis::Y : SoftMath::Axis::Z;
    return SoftMath::generateRotationMatrix33(a, axis, g_trig);
}

}  // namespace

TEST_CASE("GteMath matrixVecMul3 agrees with SoftMath") {
    for (unsigned m = 0; m < 6; m++) {
        Matrix33 mat = someMatrix(m);
        for (unsigned v = 0; v < c_vectorCount; v++) {
            Vec3 expected, got;
            SoftMath::matrixVecMul3(mat, c_vectors[v], &expected);
            GteMath::matrixVecMul3(mat, c_vectors[v], &got);
            REQUIRE(worstVec(expected, got) <= kVecTolerance);
        }
    }
}

TEST_CASE("GteMath multiplyMatrix33 agrees with SoftMath") {
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned j = 0; j < 6; j++) {
            Matrix33 expected, got;
            SoftMath::multiplyMatrix33(someMatrix(i), someMatrix(j), &expected);
            GteMath::multiplyMatrix33(someMatrix(i), someMatrix(j), &got);
            REQUIRE(worstMat(expected, got) <= kMatTolerance);
        }
    }
}

// out may alias an input. Its own case because the implementation accumulates
// into locals first, and an "optimisation" that wrote back per column would
// break here and nowhere else.
TEST_CASE("GteMath multiplyMatrix33 tolerates aliasing") {
    Matrix33 a = someMatrix(1);
    Matrix33 b = someMatrix(4);
    Matrix33 reference;
    GteMath::multiplyMatrix33(a, b, &reference);
    Matrix33 aliased = a;
    GteMath::multiplyMatrix33(aliased, b, &aliased);
    REQUIRE(worstMat(reference, aliased) == 0);
}

TEST_CASE("GteMath crossProductVec3 agrees with SoftMath") {
    for (unsigned i = 0; i < c_vectorCount; i++) {
        for (unsigned j = 0; j < c_vectorCount; j++) {
            if (i == j) continue;
            Vec3 expected, got;
            SoftMath::crossProductVec3(c_vectors[i], c_vectors[j], &expected);
            GteMath::crossProductVec3(c_vectors[i], c_vectors[j], &got);
            REQUIRE(worstVec(expected, got) <= kVecTolerance);
        }
    }
}

TEST_CASE("GteMath normalizeVec3 agrees with SoftMath") {
    for (unsigned i = 0; i < c_vectorCount; i++) {
        Vec3 expected = c_vectors[i];
        Vec3 got = c_vectors[i];
        SoftMath::normalizeVec3(&expected);
        GteMath::normalizeVec3(&got);
        REQUIRE(worstVec(expected, got) <= kNormalTolerance);
    }
}

// Agreeing with SoftMath and being correct are different claims: if both were
// wrong the same way, the comparison above would still pass. So check the
// property directly.
TEST_CASE("GteMath normalizeVec3 produces unit vectors") {
    for (unsigned i = 0; i < c_vectorCount; i++) {
        Vec3 v = c_vectors[i];
        GteMath::normalizeVec3(&v);
        FixedPoint<> sq = v.x * v.x + v.y * v.y + v.z * v.z;
        int32_t d = sq.raw() - 4096;
        if (d < 0) d = -d;
        REQUIRE(d <= 96);
    }
}

// Degenerate input, GteMath only - see the note on c_vectors for why this is
// not a comparison. A zero-length vector has no defined direction, so the
// contract is just that it returns something finite and unit rather than
// trapping.
TEST_CASE("GteMath normalizeVec3 survives a zero vector") {
    Vec3 v = {0.0_fp, 0.0_fp, 0.0_fp};
    GteMath::normalizeVec3(&v);
    FixedPoint<> sq = v.x * v.x + v.y * v.y + v.z * v.z;
    int32_t d = sq.raw() - 4096;
    if (d < 0) d = -d;
    REQUIRE(d <= 96);
}

// The seed has to land inside Newton's basin across the whole domain, not just
// near 1.0. Shifting by the whole leading-bit count instead of half of it is a
// seed for 1/x, which diverges for small inputs rather than degrading, so this
// sweeps down to something tiny on purpose.
TEST_CASE("GteMath inverse square root seed converges across the domain") {
    for (int32_t raw = 4096; raw >= 4; raw = raw * 3 / 4) {
        FixedPoint<> x(raw, FixedPoint<>::RAW);
        FixedPoint<> y = SoftMath::inverseSquareRoot(x, GteMath::inverseSquareRootSeed(x));
        FixedPoint<> check = y * y * x;  // should be 1.0 if y is 1/sqrt(x)
        int32_t d = check.raw() - 4096;
        if (d < 0) d = -d;
        REQUIRE(d <= 128);
    }
}

TEST_CASE("GteMath cubic agrees with Bezier::cubic") {
    const Vec3 a = {-1.5_fp, 0.25_fp, 0.0_fp};
    const Vec3 b = {-0.5_fp, 1.75_fp, 1.0_fp};
    const Vec3 c = {0.5_fp, -1.75_fp, 1.0_fp};
    const Vec3 d = {1.5_fp, -0.25_fp, 0.0_fp};
    for (int32_t i = 0; i <= 16; i++) {
        FixedPoint<> t(i * 256, FixedPoint<>::RAW);
        Vec3 expected = Bezier::cubic(a, b, c, d, t);
        Vec3 got = GteMath::cubic(a, b, c, d, t);
        REQUIRE(worstVec(expected, got) <= kVecTolerance);
    }
}

// Endpoints are exact by definition, so they are the one place a tolerance
// would paper over a real error.
TEST_CASE("GteMath cubic interpolates its endpoints") {
    const Vec3 a = {-1.5_fp, 0.25_fp, 0.75_fp};
    const Vec3 b = {-0.5_fp, 1.75_fp, 1.0_fp};
    const Vec3 c = {0.5_fp, -1.75_fp, 1.0_fp};
    const Vec3 d = {1.5_fp, -0.25_fp, -0.75_fp};
    REQUIRE(worstVec(GteMath::cubic(a, b, c, d, 0.0_fp), a) <= 4);
    REQUIRE(worstVec(GteMath::cubic(a, b, c, d, 1.0_fp), d) <= 4);
}

// The derivative deliberately drops the factor of three, so compare direction
// rather than magnitude. At the endpoints the analytic tangent lies along the
// first and last control-point differences.
TEST_CASE("GteMath cubicDerivative points along the control polygon") {
    const Vec3 a = {-1.5_fp, 0.25_fp, 0.0_fp};
    const Vec3 b = {-0.5_fp, 1.75_fp, 0.5_fp};
    const Vec3 c = {0.5_fp, -1.75_fp, 0.5_fp};
    const Vec3 d = {1.5_fp, -0.25_fp, 0.0_fp};
    Vec3 startExpected = {b.x - a.x, b.y - a.y, b.z - a.z};
    Vec3 endExpected = {d.x - c.x, d.y - c.y, d.z - c.z};
    SoftMath::normalizeVec3(&startExpected);
    SoftMath::normalizeVec3(&endExpected);
    Vec3 startGot = GteMath::cubicDerivative(a, b, c, d, 0.0_fp);
    Vec3 endGot = GteMath::cubicDerivative(a, b, c, d, 1.0_fp);
    GteMath::normalizeVec3(&startGot);
    GteMath::normalizeVec3(&endGot);
    REQUIRE(worstVec(startExpected, startGot) <= kNormalTolerance);
    REQUIRE(worstVec(endExpected, endGot) <= kNormalTolerance);
}

// crossProductVec3 eats the rotation matrix diagonal, because the GTE takes its
// first operand from R11/R22/R33 rather than a vector register. That is in the
// header, and comments rot, so pin it: if an implementation ever stops
// clobbering RT this fails and somebody gets to delete a warning.
TEST_CASE("GteMath crossProductVec3 clobbers the rotation diagonal") {
    GTE::writeSafe<GTE::PseudoRegister::Rotation>(someMatrix(2));
    Vec3 out;
    GteMath::crossProductVec3({1.0_fp, 0.0_fp, 0.0_fp}, {0.0_fp, 1.0_fp, 0.0_fp}, &out);
    int32_t r11 = int32_t(int16_t(GTE::readRaw<GTE::Register::R11R12>() & 0xffff));
    REQUIRE(r11 == 4096);
}
