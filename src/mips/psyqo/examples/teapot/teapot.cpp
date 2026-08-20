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

// The Utah teapot, tessellated from its 32 bicubic Bezier patches and lit
// entirely by the GTE's hardware lighting. Every existing psyqo example that
// lights anything does it on the CPU; this one uses the light-source matrix
// (LLM) and light-colour matrix (LCM) with the nccs command, which is what the
// GTE was actually built for. The teapot is plain grey; the three coloured
// directional lights are doing all of the visible work.

#include "psyqo/application.hh"
#include "psyqo/bezier.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/matrix.hh"
#include "psyqo/ordering-table.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"
#include "psyqo/font.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/vector.hh"

#include "common/syscalls/syscalls.h"

#include "teapot-data.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

namespace {

// N subdivisions per patch edge. (N+1)^2 vertices and N^2 quads per patch.
// N=4 gives 800 vertices and 512 quads over the 32 patches: enough to round
// off the body without drowning the ordering table.
constexpr unsigned N = 4;
constexpr unsigned kVertsPerPatch = (N + 1) * (N + 1);
constexpr unsigned kQuadsPerPatch = N * N;
constexpr unsigned kVertexCount = teapot::kPatchCount * kVertsPerPatch;  // 800
constexpr unsigned kQuadCount = teapot::kPatchCount * kQuadsPerPatch;    // 512

constexpr unsigned ORDERING_TABLE_SIZE = 1024;

// A quad is four vertex indices into the baked vertex/normal arrays.
struct Quad {
    uint16_t v[4];
};

class Teapot final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Trig<> m_trig;
    psyqo::Font<> m_font;
    psyqo::SimplePad m_input;
};

class TeapotScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;

    void tessellate();

    psyqo::Angle m_rot = 0;
    // Triangle, Circle and Cross switch one light each. Watching a light go
    // out is the only thing that distinguishes three lights from three vertex
    // colours; a still frame of the lit pot cannot.
    bool m_lightOn[3] = {true, true, true};

    // Where along the camera path we are, ping-ponging 0 -> 1 -> 0. The path
    // itself is evaluated on the GTE every frame, which is the realtime case
    // the accelerated Bezier exists for - a one-shot tessellation would not
    // justify it.
    psyqo::FixedPoint<> m_pathT = 0.0_fp;
    bool m_pathForward = true;

    // Baked at boot from the Bezier patches: object-space positions, unit
    // normals, and the quad connectivity.
    psyqo::GTE::PackedVec3 m_vertices[kVertexCount];
    psyqo::GTE::PackedVec3 m_normals[kVertexCount];
    Quad m_quads[kQuadCount];

    // Per-frame scratch, recomputed every frame.
    psyqo::Vertex m_projected[kVertexCount];
    uint32_t m_sz[kVertexCount];
    psyqo::Color m_shade[kVertexCount];

    psyqo::OrderingTable<ORDERING_TABLE_SIZE> m_ots[2];
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_clear[2];
    eastl::array<psyqo::Fragments::SimpleFragment<psyqo::Prim::GouraudQuad>, kQuadCount> m_frags[2];

    static constexpr psyqo::Color c_bg = {{.r = 20, .g = 22, .b = 28}};

    // A cubic Bezier the camera drifts along, in the same raw units the GTE
    // reads the packed vectors in. Evaluated once per frame with gteCubic.
    static constexpr psyqo::Vec3 c_path[4] = {
        {-1.1_fp, -0.35_fp, -0.55_fp},
        {-0.4_fp, 0.5_fp, 0.9_fp},
        {0.4_fp, -0.5_fp, 0.9_fp},
        {1.1_fp, 0.35_fp, -0.55_fp},
    };

    // Three directional lights, in world space, each a pure primary. The
    // teapot spins under them, so the coloured highlights sweep across it.
    // Rows are light directions, unit length, in world space. Screen Z runs
    // INTO the display, so a light that reaches a camera-facing surface has a
    // negative z: front normals point back out at the viewer.
    static constexpr psyqo::Matrix33 c_lightDirs = {{
        {0.501_fp, -0.602_fp, -0.622_fp},   // key, upper right front
        {-0.792_fp, -0.226_fp, -0.566_fp},  // fill, from the left
        {0.123_fp, 0.862_fp, -0.493_fp},    // rim, from below and behind
    }};
    // LCM: rows are channels, COLUMNS are lights. Column i is light i's colour.
    // A warm near-white key carries the shading; the two fills are weak and
    // saturated so they tint the shadow side without turning it into a colour
    // wheel. Three equal primaries here make the surface colour a direct
    // readout of which light reaches it, which reads as Gouraud, not lighting.
    //          key    fill   rim
    static constexpr psyqo::Matrix33 c_lightColors = {{
        {1.0_fp, 0.10_fp, 0.45_fp},   // R
        {0.94_fp, 0.22_fp, 0.14_fp},  // G
        {0.82_fp, 0.55_fp, 0.22_fp},  // B
    }};
};

#ifndef TEAPOT_VERIFY_BEZIER
#define TEAPOT_VERIFY_BEZIER 0
#endif
#if TEAPOT_VERIFY_BEZIER
int32_t s_worstBezErr = 0;
int32_t s_worstDerErr = 0;
#endif

#ifndef TEAPOT_VERIFY_MATMUL
#define TEAPOT_VERIFY_MATMUL 0
#endif
#if TEAPOT_VERIFY_MATMUL
int32_t s_worstMatErr = 0;
bool s_matReported = false;
#endif

#ifndef TEAPOT_VERIFY_NORMALIZE
#define TEAPOT_VERIFY_NORMALIZE 0
#endif
#if TEAPOT_VERIFY_NORMALIZE
int32_t s_worstNormalErr = 0;
#endif

Teapot g_teapot;
TeapotScene teapotScene;

// The derivative of a cubic Bezier is a quadratic Bezier over the differences
// of consecutive control points (times three, which drops out once we only
// want the direction). Used to get the two surface tangents, hence the normal.
psyqo::Vec3 cubicDerivative(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                            psyqo::FixedPoint<> t) {
    psyqo::FixedPoint<> mt = 1.0_fp - t;
    psyqo::Vec3 ab = {b.x - a.x, b.y - a.y, b.z - a.z};
    psyqo::Vec3 bc = {c.x - b.x, c.y - b.y, c.z - b.z};
    psyqo::Vec3 cd = {d.x - c.x, d.y - c.y, d.z - c.z};
    psyqo::FixedPoint<> f1 = mt * mt;
    psyqo::FixedPoint<> f2 = mt * t * 2;
    psyqo::FixedPoint<> f3 = t * t;
    return {
        ab.x * f1 + bc.x * f2 + cd.x * f3,
        ab.y * f1 + bc.y * f2 + cd.y * f3,
        ab.z * f1 + bc.z * f2 + cd.z * f3,
    };
}

// Cubic Bezier on the GTE.
//
// MVMVA computes Mx * Vx + Tx, and a cubic Bezier is exactly a weighted sum of
// control points, so loading three of them as the matrix COLUMNS and the
// Bernstein weights as the vector evaluates three of the four terms in one GTE
// op. The fourth rides in the translation register.
//
// This is worth having for its own sake rather than for the teapot's boot time:
// a curve evaluated per frame is how you get smooth camera motion along a 3D
// path, and that is a realtime cost, not a one-shot one.
//
// Checked against psyqo::Bezier::cubic and the software derivative at every
// evaluation with TEAPOT_VERIFY_BEZIER=1: worst component deviation 3 raw out
// of 4096 on both, over all 32 patches.
//
// Note the matrix is built from COLUMNS. Matrix33 stores rows, so a control
// point becomes a column by scattering it across the three row vectors.
psyqo::Matrix33 columnsOf(const psyqo::Vec3& c0, const psyqo::Vec3& c1, const psyqo::Vec3& c2) {
    return {{
        {c0.x, c1.x, c2.x},
        {c0.y, c1.y, c2.y},
        {c0.z, c1.z, c2.z},
    }};
}

psyqo::Vec3 gteCubic(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                     psyqo::FixedPoint<> t) {
    psyqo::FixedPoint<> mt = 1.0_fp - t;
    psyqo::FixedPoint<> mt2 = mt * mt;
    psyqo::FixedPoint<> t2 = t * t;
    psyqo::FixedPoint<> f1 = mt2 * mt;
    psyqo::FixedPoint<> f2 = mt2 * t * 3;
    psyqo::FixedPoint<> f3 = mt * t2 * 3;
    psyqo::FixedPoint<> f4 = t2 * t;

    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(columnsOf(a, b, c));
    // The fourth term as the translation vector. TR is added pre-shifted, so it
    // goes in already scaled by f4.
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Translation>(
        psyqo::Vec3{d.x * f4, d.y * f4, d.z * f4});
    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(psyqo::Vec3{f1, f2, f3});
    psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0,
                               psyqo::GTE::Kernels::TV::TR>();
    return psyqo::Vec3(psyqo::GTE::readSafe<psyqo::GTE::PseudoRegister::SV>());
}

// The derivative is a quadratic over the control-point differences, which is
// three terms and therefore needs no translation vector at all - one MVMVA and
// nothing else. The factor of three is dropped: this feeds a cross product that
// gets normalised, so only the direction survives.
psyqo::Vec3 gteCubicDerivative(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                               psyqo::FixedPoint<> t) {
    psyqo::FixedPoint<> mt = 1.0_fp - t;
    psyqo::Vec3 ab = {b.x - a.x, b.y - a.y, b.z - a.z};
    psyqo::Vec3 bc = {c.x - b.x, c.y - b.y, c.z - b.z};
    psyqo::Vec3 cd = {d.x - c.x, d.y - c.y, d.z - c.z};

    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(columnsOf(ab, bc, cd));
    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(psyqo::Vec3{mt * mt, mt * t * 2, t * t});
    psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
    return psyqo::Vec3(psyqo::GTE::readSafe<psyqo::GTE::PseudoRegister::SV>());
}

// Normalise using the GTE's leading-bit counter for the seed instead of
// SoftMath::normalizeVec3, which reaches 1/sqrt through squareRoot's
// shift-subtract loop and costs around 3588 cycles a vector on an SCPH-5501.
// Here the squared length stays on the CPU (three multiplies) and only the
// seed comes from LZCS/LZCR, feeding psyqo's existing Newton refinement.
//
// The seed wants HALF the exponent, because the target is 1/sqrt(x) and not
// 1/x. With lzcr = 31 - floor(log2(square.raw())), that is (5 + lzcr) / 2 in
// 20.12. Shifting by the whole count is a seed for the wrong function; it
// happens to be right at square == 0.0625 and diverges either side, which is
// the bug the torus example shipped with for years.
//
// LZCS and LZCR do not interlock the way the cop2 commands do, so the write
// needs its nops - hence Safe.
//
// Checked against SoftMath::normalizeVec3 over all 800 vertices with
// TEAPOT_VERIFY_NORMALIZE=1: worst component deviation 10 raw out of 4096,
// i.e. 0.24%.
// Compose two matrices on the GTE instead of in software. Deliberately keeps
// SoftMath::multiplyMatrix33's argument convention, which is out = m2 * m1, so
// this is a drop-in and the call sites do not have to be re-reasoned about.
//
// Column j of the product is m2 applied to column j of m1, which is exactly one
// MVMVA each, so this is three GTE ops against SoftMath's 27 fixed-point
// multiplies. Measured on hardware, the GTE route wins 5.46x even paying the
// matrix upload inside the call.
//
// Checked against SoftMath::multiplyMatrix33 at every call site with
// TEAPOT_VERIFY_MATMUL=1: worst element deviation 1 raw out of 4096.
//
// CLOBBERS THE ROTATION REGISTER. Both call sites here run before the frame's
// projection loads RT for real, so the collision is ordering, not a conflict -
// but any caller has to know, which is the whole argument for keeping this kind
// of thing in a library with the contract written down rather than open-coded.
void gteMultiplyMatrix33(const psyqo::Matrix33& m1, const psyqo::Matrix33& m2, psyqo::Matrix33* out) {
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(m2);
    const psyqo::Vec3 cols[3] = {
        {m1.vs[0].x, m1.vs[1].x, m1.vs[2].x},
        {m1.vs[0].y, m1.vs[1].y, m1.vs[2].y},
        {m1.vs[0].z, m1.vs[1].z, m1.vs[2].z},
    };
    psyqo::Vec3 res[3];
    for (unsigned j = 0; j < 3; j++) {
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(cols[j]);
        psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
        res[j] = psyqo::Vec3(psyqo::GTE::readSafe<psyqo::GTE::PseudoRegister::SV>());
    }
    // res[j] is column j of the product; the Matrix33 stores rows.
    out->vs[0] = {res[0].x, res[1].x, res[2].x};
    out->vs[1] = {res[0].y, res[1].y, res[2].y};
    out->vs[2] = {res[0].z, res[1].z, res[2].z};
}

void gteNormalizeVec3(psyqo::Vec3* v) {
    psyqo::FixedPoint<> square = v->x * v->x + v->y * v->y + v->z * v->z;
    if (square.raw() <= 1) {
        *v = {0.0_fp, 0.0_fp, 1.0_fp};
        return;
    }
    psyqo::GTE::write<psyqo::GTE::Register::LZCS, psyqo::GTE::Safe>(square.raw());
    auto approx = 1 << ((5 + psyqo::GTE::readRaw<psyqo::GTE::Register::LZCR>()) / 2);
    auto len = psyqo::SoftMath::inverseSquareRoot(square, psyqo::FixedPoint<>(approx, psyqo::FixedPoint<>::RAW));
    v->x *= len;
    v->y *= len;
    v->z *= len;
}


#if TEAPOT_VERIFY_MATMUL
void checkedMultiply(const psyqo::Matrix33& a, const psyqo::Matrix33& b, psyqo::Matrix33* out) {
    psyqo::Matrix33 exact;
    psyqo::SoftMath::multiplyMatrix33(a, b, &exact);
    gteMultiplyMatrix33(a, b, out);
    for (unsigned r = 0; r < 3; r++) {
        const psyqo::FixedPoint<> e[3] = {exact.vs[r].x, exact.vs[r].y, exact.vs[r].z};
        const psyqo::FixedPoint<> g[3] = {out->vs[r].x, out->vs[r].y, out->vs[r].z};
        for (unsigned c = 0; c < 3; c++) {
            int32_t d = (g[c] - e[c]).raw();
            if (d < 0) d = -d;
            if (d > s_worstMatErr) s_worstMatErr = d;
        }
    }
}
#define MULMAT(a, b, o) checkedMultiply(a, b, o)
#else
#define MULMAT(a, b, o) gteMultiplyMatrix33(a, b, o)
#endif


#if TEAPOT_VERIFY_BEZIER
int32_t worstOf(const psyqo::Vec3& x, const psyqo::Vec3& y) {
    int32_t d0 = (x.x - y.x).raw(), d1 = (x.y - y.y).raw(), d2 = (x.z - y.z).raw();
    if (d0 < 0) d0 = -d0;
    if (d1 < 0) d1 = -d1;
    if (d2 < 0) d2 = -d2;
    int32_t m = d0 > d1 ? d0 : d1;
    return d2 > m ? d2 : m;
}
psyqo::Vec3 checkedCubic(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                         psyqo::FixedPoint<> t) {
    psyqo::Vec3 e = psyqo::Bezier::cubic(a, b, c, d, t);
    psyqo::Vec3 g = gteCubic(a, b, c, d, t);
    int32_t w = worstOf(e, g);
    if (w > s_worstBezErr) s_worstBezErr = w;
    return g;
}
psyqo::Vec3 checkedDerivative(const psyqo::Vec3& a, const psyqo::Vec3& b, const psyqo::Vec3& c, const psyqo::Vec3& d,
                              psyqo::FixedPoint<> t) {
    psyqo::Vec3 e = cubicDerivative(a, b, c, d, t);
    psyqo::Vec3 g = gteCubicDerivative(a, b, c, d, t);
    int32_t w = worstOf(e, g);
    if (w > s_worstDerErr) s_worstDerErr = w;
    return g;
}
#define BEZ(a, b, c, d, t) checkedCubic(a, b, c, d, t)
#define BEZD(a, b, c, d, t) checkedDerivative(a, b, c, d, t)
#else
#define BEZ(a, b, c, d, t) gteCubic(a, b, c, d, t)
#define BEZD(a, b, c, d, t) gteCubicDerivative(a, b, c, d, t)
#endif

psyqo::Vec3 controlPoint(unsigned patch, unsigned i) {
    const auto* p = teapot::kControlPoints[teapot::kPatchIndices[patch][i]];
    return {psyqo::FixedPoint<>(p[0], psyqo::FixedPoint<>::RAW), psyqo::FixedPoint<>(p[1], psyqo::FixedPoint<>::RAW),
            psyqo::FixedPoint<>(p[2], psyqo::FixedPoint<>::RAW)};
}

}  // namespace

void TeapotScene::tessellate() {
    // The lid tip and the body bottom are collapsed patch rows where one
    // tangent vanishes, so nudge the parameters off the exact 0 and 1 edges to
    // keep every normal well defined.
    constexpr psyqo::FixedPoint<> eps = 0.002_fp;
    constexpr psyqo::FixedPoint<> span = 1.0_fp - 0.004_fp;

    unsigned vbase = 0;
    for (unsigned patch = 0; patch < teapot::kPatchCount; patch++) {
        psyqo::Vec3 cp[16];
        for (unsigned i = 0; i < 16; i++) cp[i] = controlPoint(patch, i);

        for (unsigned iu = 0; iu <= N; iu++) {
            psyqo::FixedPoint<> u = eps + span * psyqo::FixedPoint<>(int32_t(iu), 0) / int32_t(N);
            for (unsigned iv = 0; iv <= N; iv++) {
                psyqo::FixedPoint<> v = eps + span * psyqo::FixedPoint<>(int32_t(iv), 0) / int32_t(N);

                // Evaluate the surface point: four row curves at v, then across
                // at u. Same nesting for the u-tangent; the v-tangent takes the
                // row derivatives across at u.
                psyqo::Vec3 row[4], drow[4];
                for (unsigned r = 0; r < 4; r++) {
                    row[r] = BEZ(cp[r * 4 + 0], cp[r * 4 + 1], cp[r * 4 + 2], cp[r * 4 + 3], v);
                    drow[r] = BEZD(cp[r * 4 + 0], cp[r * 4 + 1], cp[r * 4 + 2], cp[r * 4 + 3], v);
                }
                psyqo::Vec3 point = BEZ(row[0], row[1], row[2], row[3], u);
                psyqo::Vec3 du = BEZD(row[0], row[1], row[2], row[3], u);
                psyqo::Vec3 dv = BEZ(drow[0], drow[1], drow[2], drow[3], u);

                // Outward normal: cross(dv, du), not the other way round. Checked
                // against the closed surface rather than by eye - summing
                // (centroid . n) * area over the whole mesh gives +75.7 for this
                // order and -75.7 for the reverse, so this is the one pointing
                // out. Getting it backwards is survivable on the convex body,
                // because flipping the light sign hides it there, and then the
                // lid is where the two errors stop cancelling.
                psyqo::Vec3 normal = {dv.y * du.z - dv.z * du.y, dv.z * du.x - dv.x * du.z, dv.x * du.y - dv.y * du.x};
                // At a collapsed patch corner (the lid tip, the body underside) a
                // tangent can round to zero in fixed point even after the eps
                // nudge, and normalizing that divides by zero. Fall back to the
                // radial direction, which is a decent outward guess there.
                psyqo::FixedPoint<> lensq = normal.x * normal.x + normal.y * normal.y + normal.z * normal.z;
                if (lensq < 0.01_fp) {
                    normal = {point.x, point.y, 0.0_fp};
                    psyqo::FixedPoint<> rsq = normal.x * normal.x + normal.y * normal.y + normal.z * normal.z;
                    if (rsq < 0.01_fp) normal = {0.0_fp, 0.0_fp, 1.0_fp};
                }
#if TEAPOT_VERIFY_NORMALIZE
                psyqo::Vec3 exact = normal;
                psyqo::SoftMath::normalizeVec3(&exact);
                gteNormalizeVec3(&normal);
                {
                    int32_t dx = (normal.x - exact.x).raw();
                    int32_t dy = (normal.y - exact.y).raw();
                    int32_t dz = (normal.z - exact.z).raw();
                    if (dx < 0) dx = -dx;
                    if (dy < 0) dy = -dy;
                    if (dz < 0) dz = -dz;
                    int32_t d = dx > dy ? dx : dy;
                    if (dz > d) d = dz;
                    if (d > s_worstNormalErr) s_worstNormalErr = d;
                }
#else
                gteNormalizeVec3(&normal);
#endif

                // The dataset sits on the z=0 ground plane with the spout out
                // along +x, so recentre it on the origin before packing.
                point.x -= 0.26_fp;
                point.z -= 1.575_fp;
                unsigned idx = vbase + iu * (N + 1) + iv;
                m_vertices[idx] = psyqo::GTE::PackedVec3(point);
                m_normals[idx] = psyqo::GTE::PackedVec3(normal);
            }
        }
        vbase += kVertsPerPatch;
    }

    unsigned q = 0;
    for (unsigned patch = 0; patch < teapot::kPatchCount; patch++) {
        unsigned base = patch * kVertsPerPatch;
        for (unsigned iu = 0; iu < N; iu++) {
            for (unsigned iv = 0; iv < N; iv++) {
                unsigned a = base + iu * (N + 1) + iv;
                // PS1 quads are two triangles ABC and BCD, so the four points
                // go in a Z, not around the ring. A ring order draws a bowtie.
                m_quads[q].v[0] = a;
                m_quads[q].v[1] = a + 1;
                m_quads[q].v[2] = a + (N + 1);
                m_quads[q].v[3] = a + (N + 1) + 1;
                q++;
            }
        }
    }
}

void Teapot::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Teapot::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&teapotScene);
}

void TeapotScene::start(StartReason reason) {
    tessellate();
#if TEAPOT_VERIFY_NORMALIZE
    ramsyscall_printf("NORMALIZE worst component error: %d raw (4096 = 1.0)\n", s_worstNormalErr);
#endif
#if TEAPOT_VERIFY_BEZIER
    ramsyscall_printf("BEZIER worst: point %d  derivative %d raw (4096 = 1.0)\n", s_worstBezErr, s_worstDerErr);
#endif

    g_teapot.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        switch (event.button) {
            case psyqo::SimplePad::Button::Triangle: m_lightOn[0] = !m_lightOn[0]; break;
            case psyqo::SimplePad::Button::Circle: m_lightOn[1] = !m_lightOn[1]; break;
            case psyqo::SimplePad::Button::Cross: m_lightOn[2] = !m_lightOn[2]; break;
            default: break;
        }
    });

    // Projection context, set once. The teapot lives around the origin and we
    // push it back on Z each frame.
    psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
    psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(300);
    // The teapot is ~3.5 units, which is 14438 in the 4.12 packed vectors the GTE
    // reads as plain integers, so it has to sit tens of thousands of units away or
    // the near half of it lands behind the eye and the divide saturates.
    psyqo::GTE::write<psyqo::GTE::Register::ZSF3, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 3);
    psyqo::GTE::write<psyqo::GTE::Register::ZSF4, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 4);

    // Lighting context that does not change: the light colours (LCM), a low
    // ambient (BK), and the grey material colour that nccs multiplies the lit
    // result by.
    psyqo::GTE::write<psyqo::GTE::Register::RBK, psyqo::GTE::Unsafe>(0x180);
    psyqo::GTE::write<psyqo::GTE::Register::GBK, psyqo::GTE::Unsafe>(0x180);
    psyqo::GTE::write<psyqo::GTE::Register::BBK, psyqo::GTE::Unsafe>(0x180);
    // On an UNTEXTURED primitive full brightness is 0xff; 0x80 is the neutral
    // point for texture blending, and using it here halves the whole image.
    psyqo::GTE::write<psyqo::GTE::Register::RGB, psyqo::GTE::Unsafe>(0x00ffffff);
}

void TeapotScene::frame() {
    int parity = gpu().getParity();
    auto& ot = m_ots[parity];
    auto& clear = m_clear[parity];
    auto& frags = m_frags[parity];

    gpu().getNextClear(clear.primitive, c_bg);
    gpu().chain(clear);

    // Spin about two axes.
    // The Newell data is Z-up and the screen is Y-down, and psyqo's X rotation
    // sends +Z to +Y, so standing the pot up wants a NEGATIVE quarter turn.
    // then spin it, then tilt the whole thing towards the camera.
    auto standUp = psyqo::SoftMath::generateRotationMatrix33(-0.5_pi, psyqo::SoftMath::Axis::X, g_teapot.m_trig);
    auto spin = psyqo::SoftMath::generateRotationMatrix33(m_rot, psyqo::SoftMath::Axis::Y, g_teapot.m_trig);
    auto tilt = psyqo::SoftMath::generateRotationMatrix33(-0.12_pi, psyqo::SoftMath::Axis::X, g_teapot.m_trig);
    // multiplyMatrix33(A, B) composes so that A's rotation happens FIRST, so the
    // pot is stood up, then spun about the (now vertical) screen Y, then the
    // whole thing is tipped towards the camera.
    psyqo::Matrix33 transform;
    MULMAT(standUp, spin, &transform);
    MULMAT(transform, tilt, &transform);

    // Camera drift along the Bezier path. This runs BEFORE the projection
    // context is loaded, because gteCubic uses RT and TR as scratch - the same
    // ordering constraint gteMultiplyMatrix33 has.
    psyqo::Vec3 cam = gteCubic(c_path[0], c_path[1], c_path[2], c_path[3], m_pathT);
    if (m_pathForward) {
        m_pathT += 0.0025_fp;
        if (m_pathT >= 1.0_fp) { m_pathT = 1.0_fp; m_pathForward = false; }
    } else {
        m_pathT -= 0.0025_fp;
        if (m_pathT <= 0.0_fp) { m_pathT = 0.0_fp; m_pathForward = true; }
    }

    // ---- Pass 1: project every vertex. ----
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);
    psyqo::GTE::write<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>((cam.x * 2600).integer<1>());
    psyqo::GTE::write<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>((cam.y * 2600).integer<1>());
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(32000 + (cam.z * 5200).integer<1>());

    unsigned i = 0;
    for (; i + 3 <= kVertexCount; i += 3) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_vertices[i + 0]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_vertices[i + 1]);
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_vertices[i + 2]);
        psyqo::GTE::Kernels::rtpt();
        psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&m_projected[i + 0].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&m_projected[i + 1].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&m_projected[i + 2].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ1>(reinterpret_cast<uint32_t*>(&m_sz[i + 0]));
        psyqo::GTE::read<psyqo::GTE::Register::SZ2>(reinterpret_cast<uint32_t*>(&m_sz[i + 1]));
        psyqo::GTE::read<psyqo::GTE::Register::SZ3>(reinterpret_cast<uint32_t*>(&m_sz[i + 2]));
    }
    for (; i < kVertexCount; i++) {
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_vertices[i]);
        psyqo::GTE::Kernels::rtps();
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&m_projected[i].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ3>(reinterpret_cast<uint32_t*>(&m_sz[i]));
    }

    // ---- Pass 2: light every vertex. ----
    // The light directions live in world space, so rotate them into object
    // space by folding the model rotation into the light matrix: with LLM =
    // worldLights * R, the row-dot-normal that nccs computes equals
    // worldLight . (R * normal), i.e. the lit band stays fixed as the pot spins.
    psyqo::Matrix33 llm;
    MULMAT(transform, c_lightDirs, &llm);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Light>(llm);

    // Note the argument order: multiplyMatrix33(m1, m2) computes m2 * m1, and
    // what we want is (lights * rotation) so that each LLM row dotted with an
    // object-space normal equals that world light dotted with the rotated
    // normal. The other order silently rotates the lights by the wrong frame.

    // Switching a light off means zeroing its COLUMN of the colour matrix,
    // which is that light's colour. Zeroing a row would kill one channel of
    // all three lights instead, and that difference is the whole point of the
    // two-matrix split.
    psyqo::Matrix33 lcm = c_lightColors;
    for (unsigned row = 0; row < 3; row++) {
        if (!m_lightOn[0]) lcm.vs[row].x = 0.0_fp;
        if (!m_lightOn[1]) lcm.vs[row].y = 0.0_fp;
        if (!m_lightOn[2]) lcm.vs[row].z = 0.0_fp;
    }
    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::Color>(lcm);
    for (i = 0; i < kVertexCount; i++) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_normals[i]);
        psyqo::GTE::Kernels::nccs();
        // RGB2's top byte is the CODE field, not colour; it must not reach the
        // primitive's colour words.
        m_shade[i].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB2>() & 0x00ffffff;
    }

    // ---- Pass 3: cull, depth-sort, assemble. ----
    unsigned drawn = 0;
    for (unsigned qi = 0; qi < kQuadCount; qi++) {
        const auto& quad = m_quads[qi];
        const auto& pa = m_projected[quad.v[0]];
        const auto& pb = m_projected[quad.v[1]];
        const auto& pc = m_projected[quad.v[2]];
        const auto& pd = m_projected[quad.v[3]];

        // Backface cull off the projected screen coordinates.
        psyqo::GTE::write<psyqo::GTE::Register::SXY0, psyqo::GTE::Unsafe>(pa.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY1, psyqo::GTE::Unsafe>(pb.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>(pc.packed);
        psyqo::GTE::Kernels::nclip();
        int32_t mac0 = 0;
        psyqo::GTE::read<psyqo::GTE::Register::MAC0>(reinterpret_cast<uint32_t*>(&mac0));
        // Quad points go in a Z, so the screen winding of A,B,C is the opposite
        // of the ring order cube.cpp uses; keep the faces whose cross product
        // comes out positive.
        if (mac0 >= 0) continue;

        int32_t z = int32_t((m_sz[quad.v[0]] + m_sz[quad.v[1]] + m_sz[quad.v[2]] + m_sz[quad.v[3]]) >> 2);
        z = (z * ORDERING_TABLE_SIZE) >> 16;
        if (z < 0 || z >= ORDERING_TABLE_SIZE) continue;

        auto& frag = frags[drawn];
        auto& prim = frag.primitive;
        prim.setPointA(pa);
        prim.setPointB(pb);
        prim.setPointC(pc);
        prim.setPointD(pd);
        prim.setColorA(m_shade[quad.v[0]]);
        prim.setColorB(m_shade[quad.v[1]]);
        prim.setColorC(m_shade[quad.v[2]]);
        prim.setColorD(m_shade[quad.v[3]]);
        prim.setOpaque();
        ot.insert(frag, z);
        drawn++;
    }

#if TEAPOT_VERIFY_MATMUL
    if (!s_matReported) {
        s_matReported = true;
        ramsyscall_printf("MATMUL worst element error: %d raw (4096 = 1.0)\n", s_worstMatErr);
    }
#endif
    gpu().chain(ot);

    static constexpr psyqo::Color c_on = {{.r = 0xff, .g = 0xff, .b = 0xff}};
    static constexpr psyqo::Color c_off = {{.r = 0x50, .g = 0x50, .b = 0x58}};
    // The system font's glyphs are 8x16, so the lines step by 16 plus a little
    // leading rather than by an eyeballed 12.
    static constexpr int16_t c_lineHeight = 18;
    static constexpr int16_t c_textTop = 6;
    g_teapot.m_font.chainprintf(gpu(), {{.x = 6, .y = c_textTop}}, m_lightOn[0] ? c_on : c_off, "[Tri] key");
    g_teapot.m_font.chainprintf(gpu(), {{.x = 6, .y = int16_t(c_textTop + c_lineHeight)}},
                                m_lightOn[1] ? c_on : c_off, "[Cir] fill");
    g_teapot.m_font.chainprintf(gpu(), {{.x = 6, .y = int16_t(c_textTop + 2 * c_lineHeight)}},
                                m_lightOn[2] ? c_on : c_off, "[Cro] rim");

    m_rot += 0.004_pi;
}

int main() { return g_teapot.run(); }
