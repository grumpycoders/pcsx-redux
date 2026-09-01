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
#include "psyqo/fixed-point.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-math.hh"
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
    // Finished GP0 first-words: the primitive's command byte fused with the lit
    // colour by the GTE. Color already models this - its `user` byte IS the top
    // byte the GP0 command lives in - so there is no reason to drop to a raw
    // word here.
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

Teapot g_teapot;
TeapotScene teapotScene;

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
                    row[r] = psyqo::GteMath::cubic(cp[r * 4 + 0], cp[r * 4 + 1], cp[r * 4 + 2], cp[r * 4 + 3], v);
                    drow[r] = psyqo::GteMath::cubicDerivative(cp[r * 4 + 0], cp[r * 4 + 1], cp[r * 4 + 2], cp[r * 4 + 3], v);
                }
                psyqo::Vec3 point = psyqo::GteMath::cubic(row[0], row[1], row[2], row[3], u);
                psyqo::Vec3 du = psyqo::GteMath::cubicDerivative(row[0], row[1], row[2], row[3], u);
                psyqo::Vec3 dv = psyqo::GteMath::cubic(drow[0], drow[1], drow[2], drow[3], u);

                // Outward normal: cross(dv, du), not the other way round. Checked
                // against the closed surface rather than by eye - summing
                // (centroid . n) * area over the whole mesh gives +75.7 for this
                // order and -75.7 for the reverse, so this is the one pointing
                // out. Getting it backwards is survivable on the convex body,
                // because flipping the light sign hides it there, and then the
                // lid is where the two errors stop cancelling.
                psyqo::Vec3 normal;
                psyqo::GteMath::crossProductVec3(dv, du, &normal);
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
                psyqo::GteMath::normalizeVec3(&normal);

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
    // RGBC is written per frame in frame(), because its top byte carries the
    // primitive command the GTE fuses into each colour. On an UNTEXTURED
    // primitive full brightness is 0xff; 0x80 is the neutral point for texture
    // blending and using it here would halve the whole image.
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
    psyqo::GteMath::multiplyMatrix33(standUp, spin, &transform);
    psyqo::GteMath::multiplyMatrix33(transform, tilt, &transform);

    // Camera drift along the Bezier path. This runs BEFORE the projection
    // context is loaded, because gteCubic uses RT and TR as scratch - the same
    // ordering constraint GteMath::multiplyMatrix33 has. Both are documented in
    // gte-math.hh: the clobber list is the real API surface of these.
    psyqo::Vec3 cam = psyqo::GteMath::cubic(c_path[0], c_path[1], c_path[2], c_path[3], m_pathT);
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
    psyqo::GteMath::multiplyMatrix33(transform, c_lightDirs, &llm);
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

    // RGBC's top byte is CODE, and the GTE fuses it into every colour it
    // produces. A GP0 polygon's first word is the command in bits 31-24 and
    // vertex A's colour in 23-0, so loading CODE with the primitive's own
    // command byte means the colour FIFO hands back finished command words: no
    // masking, and the assembly below is a word store rather than a
    // read-modify-write. The material stays 0xff - full brightness on an
    // untextured primitive.
    psyqo::GTE::write<psyqo::GTE::Register::RGB, psyqo::GTE::Unsafe>(
        m_frags[parity][0].primitive.getCommandWord() | 0x00ffffff);

    // Three normals at a time, exactly like rtpt above. NCCT is 39 cycles
    // against 51 for three NCCS, and it costs one kernel issue instead of
    // three.
    for (i = 0; i + 3 <= kVertexCount; i += 3) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_normals[i + 0]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_normals[i + 1]);
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_normals[i + 2]);
        psyqo::GTE::Kernels::ncct();
        m_shade[i + 0].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB0>();
        m_shade[i + 1].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB1>();
        m_shade[i + 2].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB2>();
    }
    for (; i < kVertexCount; i++) {
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_normals[i]);
        psyqo::GTE::Kernels::nccs();
        m_shade[i].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB2>();
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
        // Each of these is already a finished word: the command byte fused with
        // the colour by the GTE. Vertex A's lands in the command slot, which is
        // where a GP0 polygon keeps it. The other three are colour-only words
        // whose top byte the GPU ignores.
        prim.setColorAPacked(m_shade[quad.v[0]].packed);
        prim.colorB = m_shade[quad.v[1]];
        prim.colorC = m_shade[quad.v[2]];
        prim.colorD = m_shade[quad.v[3]];
        ot.insert(frag, z);
        drawn++;
    }

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
