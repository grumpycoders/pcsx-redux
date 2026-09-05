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

// Conway's Game of Life on a 24x24 wrapping board, drawn as a field of small
// grey cubes and lit by the GTE's hardware lighting, with the camera orbiting
// the field.
//
// The teapot example lights a smooth surface, where every vertex has its own
// normal and the whole point is that the shading varies continuously. This is
// the opposite case and it is worth having both: a field of axis-aligned cubes
// has exactly SIX distinct normals no matter how many cubes are on the board,
// so the entire lighting cost of a frame is two ncct issues, once, before the
// geometry loop starts. Six hundred cubes cost the same to light as one. That
// is not a trick specific to Life - it is the general shape of lighting any
// instanced, uniformly-oriented geometry on this hardware, and it is invisible
// if the only example you have lights per vertex.
//
// The second thing this example is for: the cubes are instances of ONE set of
// eight corner offsets. Rather than building a per-cube vertex array on the
// CPU, the rotation matrix is loaded once and the GTE's translation vector is
// rewritten per cube, so each cube costs three ctc2 writes and four kernel
// issues and no vertex maths at all. Grid positions are accumulated with adds
// as the loop walks the board, so there is not a single multiply in the inner
// loop either.

#include "psyqo/application.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/font.hh"
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
#include "psyqo/soft-math.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/vector.hh"

#include "life-rules.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

namespace {

// Distance between cube centres, and the cube's half-extent. The gap between
// the two is what keeps neighbouring cells readable as separate cells rather
// than as one slab.
constexpr psyqo::FixedPoint<> kPitch = 0.28_fp;
constexpr psyqo::FixedPoint<> kHalf = 0.105_fp;

// How long a generation is held on screen, in frames.
constexpr unsigned kFramesPerGeneration = 18;
// At most three faces of a convex box can face any single viewpoint, so this is
// a hard bound and not an estimate.
constexpr unsigned kMaxQuads = life::kCellCount * 3;
constexpr unsigned ORDERING_TABLE_SIZE = 1024;

// How far the board sits from the eye, in the raw 4.12 units the GTE reads the
// packed vectors in. Two constraints pin this down and they pull in opposite
// directions. SZ saturates at 16 bits, so the far corner of the board has to
// come out under 65535 or the depth sort collapses at the back; and the board
// has to be far enough away that the near corner does not swing behind the eye
// as the camera orbits. The board's half-diagonal is 24 * 0.28 / 2 * sqrt(2) =
// 4.75 units = 19470 raw, so anything in the low thirty thousands satisfies
// both with room to spare.
constexpr int32_t kCameraDistance = 42000;
// The board's centre is pushed a little UP the screen, because the tilt puts the
// near edge lower and larger and an image centred on the board's middle runs off
// the bottom of the frame. Screen Y is down, so lifting is negative.
constexpr int32_t kCameraLift = -1500;

// Down-tilt of the camera. psyqo's X rotation sends +Z to +Y and the screen's Y
// runs downwards, so looking DOWN at a board lying in the XZ plane wants a
// negative angle.
constexpr psyqo::Angle kElevation = -0.235_pi;
constexpr psyqo::Angle kOrbitPerFrame = 0.0013_pi;

// The eight corners of a cube, indexed by bit: 1 = +x, 2 = +y, 4 = +z.
constexpr unsigned kCornerCount = 8;
// The six faces, each as four corner indices in a Z - the order the GPU wants,
// where it draws triangles ABC and BCD. Each is derived from the ring that runs
// counter-clockwise seen from OUTSIDE the cube (p0, p1, p2, p3) by emitting
// p0, p1, p3, p2; keeping the ring in the comment is what makes the winding
// checkable by hand rather than by eye.
struct Face {
    uint8_t v[4];
};
constexpr Face kFaces[6] = {
    {{1, 3, 5, 7}},  // +X, ring 1,3,7,5
    {{0, 4, 2, 6}},  // -X, ring 0,4,6,2
    {{2, 6, 3, 7}},  // +Y, ring 2,6,7,3
    {{0, 1, 4, 5}},  // -Y, ring 0,1,5,4
    {{4, 5, 6, 7}},  // +Z, ring 4,5,7,6
    {{0, 2, 1, 3}},  // -Z, ring 0,2,3,1
};

class Life3D final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Trig<> m_trig;
    psyqo::Font<> m_font;
    psyqo::SimplePad m_input;
};

class Life3DScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;

    // --- simulation ---
    life::Sim m_sim{0x9e3779b9};
    unsigned m_frameInGeneration = 0;
    bool m_paused = false;

    // --- rendering ---
    psyqo::Angle m_orbit = 0;
    bool m_lightOn[3] = {true, true, true};

    psyqo::GTE::PackedVec3 m_corners[kCornerCount];
    psyqo::GTE::PackedVec3 m_faceNormals[6];
    psyqo::Color m_faceColor[6];

    psyqo::OrderingTable<ORDERING_TABLE_SIZE> m_ots[2];
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_clear[2];
    psyqo::Fragments::SimpleFragment<psyqo::Prim::Quad> m_frags[2][kMaxQuads];

    static constexpr psyqo::Color c_bg = {{.r = 12, .g = 13, .b = 18}};

    // Three directional lights in view space, so they stay put while the board
    // turns underneath them and the lit face of a cube changes as it comes
    // round. Rows are light directions, unit length, and each points FROM the
    // surface TOWARDS the light, because nccs clamps the row-dot-normal at zero
    // and a surface facing away has to come out negative. Screen Y runs down
    // and screen Z runs into the display, so "above and in front of the viewer"
    // is negative in both.
    static constexpr psyqo::Matrix33 c_lightDirs = {{
        {0.336_fp, -0.840_fp, -0.426_fp},   // key, high and slightly right
        {-0.760_fp, -0.194_fp, -0.620_fp},  // fill, from the left and low
        {0.402_fp, 0.512_fp, -0.759_fp},    // rim, from below, kicks the near faces
    }};
    // LCM: rows are colour channels, COLUMNS are lights, so column i is the
    // colour of light i. Deleting a light means zeroing its column. Zeroing a
    // ROW would remove one channel from all three lights at once, which is a
    // different and much less useful thing, and that asymmetry is the whole
    // reason the GTE splits direction and colour across two matrices.
    //          key     fill    rim
    static constexpr psyqo::Matrix33 c_lightColors = {{
        {0.95_fp, 0.22_fp, 0.54_fp},  // R
        {0.93_fp, 0.30_fp, 0.36_fp},  // G
        {0.88_fp, 0.52_fp, 0.22_fp},  // B
    }};
};

Life3D g_life3d;
Life3DScene g_scene;

}  // namespace

void Life3D::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Life3D::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&g_scene);
}

void Life3DScene::start(StartReason reason) {
    for (unsigned i = 0; i < kCornerCount; i++) {
        psyqo::Vec3 c = {(i & 1) ? kHalf : -kHalf, (i & 2) ? kHalf : -kHalf, (i & 4) ? kHalf : -kHalf};
        m_corners[i] = psyqo::GTE::PackedVec3(c);
    }
    // One unit normal per face, in the board's own space. The GTE reads these
    // as plain integers in the same 4.12 the packed vectors use, so "one" here
    // is 4096.
    static constexpr psyqo::Vec3 c_normals[6] = {
        {1.0_fp, 0.0_fp, 0.0_fp}, {-1.0_fp, 0.0_fp, 0.0_fp}, {0.0_fp, 1.0_fp, 0.0_fp},
        {0.0_fp, -1.0_fp, 0.0_fp}, {0.0_fp, 0.0_fp, 1.0_fp}, {0.0_fp, 0.0_fp, -1.0_fp},
    };
    for (unsigned i = 0; i < 6; i++) m_faceNormals[i] = psyqo::GTE::PackedVec3(c_normals[i]);

    g_life3d.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        switch (event.button) {
            case psyqo::SimplePad::Button::Triangle: m_lightOn[0] = !m_lightOn[0]; break;
            case psyqo::SimplePad::Button::Circle: m_lightOn[1] = !m_lightOn[1]; break;
            case psyqo::SimplePad::Button::Cross: m_lightOn[2] = !m_lightOn[2]; break;
            case psyqo::SimplePad::Button::Square: m_paused = !m_paused; break;
            case psyqo::SimplePad::Button::Start: m_sim.reseed(); break;
            default: break;
        }
    });

    // Projection context. Unlike the teapot, the translation vector is NOT part
    // of this: it is rewritten once per cube in frame(), which is what makes
    // every cube share one set of corner vectors.
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(330);
    psyqo::GTE::write<psyqo::GTE::Register::ZSF3, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 3);
    psyqo::GTE::write<psyqo::GTE::Register::ZSF4, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 4);

    // A cool, dim ambient so the unlit faces read as dark grey rather than as
    // holes in the image. These are 1.19.12, so 0x150 is about 8%.
    psyqo::GTE::write<psyqo::GTE::Register::RBK, psyqo::GTE::Unsafe>(0x0e0);
    psyqo::GTE::write<psyqo::GTE::Register::GBK, psyqo::GTE::Unsafe>(0x0f0);
    psyqo::GTE::write<psyqo::GTE::Register::BBK, psyqo::GTE::Unsafe>(0x130);

    // The material the lights multiply against: a flat neutral grey with a hint
    // of blue. On an UNTEXTURED primitive 0xff is full brightness - 0x80 is the
    // neutral point for texture blending, and using it here would halve the
    // whole image for no reason.
    psyqo::GTE::write<psyqo::GTE::Register::RGB, psyqo::GTE::Unsafe>(0x00989ca4);
}

void Life3DScene::frame() {
    if (!m_paused && ++m_frameInGeneration >= kFramesPerGeneration) {
        m_frameInGeneration = 0;
        m_sim.advance();
    }

    int parity = gpu().getParity();
    auto& ot = m_ots[parity];
    auto& clear = m_clear[parity];
    auto& frags = m_frags[parity];

    gpu().getNextClear(clear.primitive, c_bg);
    gpu().chain(clear);

    // Orbit about the board's vertical axis, then tip the whole thing towards
    // the viewer. multiplyMatrix33(A, B) composes so that A happens FIRST.
    auto spin = psyqo::SoftMath::generateRotationMatrix33(m_orbit, psyqo::SoftMath::Axis::Y, g_life3d.m_trig);
    auto tilt = psyqo::SoftMath::generateRotationMatrix33(kElevation, psyqo::SoftMath::Axis::X, g_life3d.m_trig);
    psyqo::Matrix33 transform;
    psyqo::GteMath::multiplyMatrix33(spin, tilt, &transform);

    // ---- Light the six faces, once, for the whole board. ----
    // This has to happen before the rotation matrix and the translation vector
    // are loaded below, because GteMath::multiplyMatrix33 uses RT and TR as
    // scratch. The clobber list is the real API surface of these helpers.
    psyqo::Matrix33 llm;
    psyqo::GteMath::multiplyMatrix33(transform, c_lightDirs, &llm);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Light>(llm);

    psyqo::Matrix33 lcm = c_lightColors;
    for (unsigned row = 0; row < 3; row++) {
        if (!m_lightOn[0]) lcm.vs[row].x = 0.0_fp;
        if (!m_lightOn[1]) lcm.vs[row].y = 0.0_fp;
        if (!m_lightOn[2]) lcm.vs[row].z = 0.0_fp;
    }
    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::Color>(lcm);

    for (unsigned i = 0; i < 6; i += 3) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_faceNormals[i + 0]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_faceNormals[i + 1]);
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_faceNormals[i + 2]);
        psyqo::GTE::Kernels::ncct();
        m_faceColor[i + 0].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB0>();
        m_faceColor[i + 1].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB1>();
        m_faceColor[i + 2].packed = psyqo::GTE::readRaw<psyqo::GTE::Register::RGB2>();
    }

    // ---- Walk the board, one cube per live cell. ----
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);

    // Where one step along the board's X and Z axes lands after rotation. A
    // rotation matrix applied to (kPitch, 0, 0) is just kPitch times its first
    // COLUMN, and psyqo's Matrix33 stores rows, hence the transposed look.
    const int32_t stepXx = (transform.vs[0].x * kPitch).raw();
    const int32_t stepXy = (transform.vs[1].x * kPitch).raw();
    const int32_t stepXz = (transform.vs[2].x * kPitch).raw();
    const int32_t stepZx = (transform.vs[0].z * kPitch).raw();
    const int32_t stepZy = (transform.vs[1].z * kPitch).raw();
    const int32_t stepZz = (transform.vs[2].z * kPitch).raw();

    // Cell (0,0) in camera space: the board's centre pushed back to the camera
    // distance, minus half a board along each axis.
    const int32_t halfW = int32_t(life::kGridW - 1);
    const int32_t halfH = int32_t(life::kGridH - 1);
    const int32_t originX = -(halfW * stepXx + halfH * stepZx) / 2;
    const int32_t originY = kCameraLift - (halfW * stepXy + halfH * stepZy) / 2;
    const int32_t originZ = kCameraDistance - (halfW * stepXz + halfH * stepZz) / 2;

    unsigned drawn = 0;
    psyqo::Vertex projected[kCornerCount];
    uint32_t sz[kCornerCount];

    int32_t rowX = originX, rowY = originY, rowZ = originZ;
    for (unsigned gy = 0; gy < life::kGridH; gy++) {
        int32_t cx = rowX, cy = rowY, cz = rowZ;
        for (unsigned gx = 0; gx < life::kGridW; gx++) {
            if (m_sim.board.at(gx, gy)) {
                // The cube's centre IS the GTE's translation vector, so the
                // eight corner offsets below are the same eight vectors for
                // every cube on the board.
                psyqo::GTE::write<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>(cx);
                psyqo::GTE::write<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>(cy);
                psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(cz);

                // Eight corners: two rtpt triples and a pair of rtps. rtpt is
                // three transforms for one kernel issue, so the split is 3+3+1+1
                // rather than eight singles.
                for (unsigned i = 0; i < 6; i += 3) {
                    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_corners[i + 0]);
                    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_corners[i + 1]);
                    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_corners[i + 2]);
                    psyqo::GTE::Kernels::rtpt();
                    psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&projected[i + 0].packed);
                    psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&projected[i + 1].packed);
                    psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i + 2].packed);
                    psyqo::GTE::read<psyqo::GTE::Register::SZ1>(&sz[i + 0]);
                    psyqo::GTE::read<psyqo::GTE::Register::SZ2>(&sz[i + 1]);
                    psyqo::GTE::read<psyqo::GTE::Register::SZ3>(&sz[i + 2]);
                }
                for (unsigned i = 6; i < kCornerCount; i++) {
                    psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_corners[i]);
                    psyqo::GTE::Kernels::rtps();
                    psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i].packed);
                    psyqo::GTE::read<psyqo::GTE::Register::SZ3>(&sz[i]);
                }

                for (unsigned f = 0; f < 6; f++) {
                    if (drawn >= kMaxQuads) break;
                    const auto& face = kFaces[f];
                    const auto& pa = projected[face.v[0]];
                    const auto& pb = projected[face.v[1]];
                    const auto& pc = projected[face.v[2]];
                    const auto& pd = projected[face.v[3]];

                    // Backface cull on the projected screen coordinates. The
                    // four points go in a Z, so the winding of A,B,C is the
                    // opposite of the ring order, and the faces to keep are the
                    // ones whose cross product comes out negative.
                    psyqo::GTE::write<psyqo::GTE::Register::SXY0, psyqo::GTE::Unsafe>(pa.packed);
                    psyqo::GTE::write<psyqo::GTE::Register::SXY1, psyqo::GTE::Unsafe>(pb.packed);
                    psyqo::GTE::write<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>(pc.packed);
                    psyqo::GTE::Kernels::nclip();
                    int32_t mac0 = 0;
                    psyqo::GTE::read<psyqo::GTE::Register::MAC0>(reinterpret_cast<uint32_t*>(&mac0));
                    if (mac0 >= 0) continue;

                    int32_t z =
                        int32_t((sz[face.v[0]] + sz[face.v[1]] + sz[face.v[2]] + sz[face.v[3]]) >> 2);
                    z = (z * ORDERING_TABLE_SIZE) >> 16;
                    if (z < 0 || z >= ORDERING_TABLE_SIZE) continue;

                    auto& frag = frags[drawn];
                    auto& prim = frag.primitive;
                    prim.setPointA(pa);
                    prim.setPointB(pb);
                    prim.setPointC(pc);
                    prim.setPointD(pd);
                    // Six colours for the whole board, computed above. A
                    // GouraudQuad would carry four copies of the same colour
                    // and three extra words per face for no visible difference:
                    // a flat face lit by directional lights IS flat.
                    prim.setColor(m_faceColor[f]);
                    ot.insert(frag, z);
                    drawn++;
                }
            }
            cx += stepXx;
            cy += stepXy;
            cz += stepXz;
        }
        rowX += stepZx;
        rowY += stepZy;
        rowZ += stepZz;
    }

    gpu().chain(ot);

    static constexpr psyqo::Color c_hud = {{.r = 0xa0, .g = 0xa8, .b = 0xb8}};
    static constexpr psyqo::Color c_on = {{.r = 0xff, .g = 0xff, .b = 0xff}};
    static constexpr psyqo::Color c_off = {{.r = 0x48, .g = 0x48, .b = 0x50}};
    // The system font's glyphs are 8x16, so lines step by 16 plus leading.
    static constexpr int16_t c_lineHeight = 18;
    auto& font = g_life3d.m_font;
    font.chainprintf(gpu(), {{.x = 6, .y = 6}}, c_hud, "gen %u  pop %u%s", m_sim.generation, m_sim.population,
                     m_paused ? "  [paused]" : "");
    font.chainprintf(gpu(), {{.x = 6, .y = int16_t(6 + c_lineHeight)}}, m_lightOn[0] ? c_on : c_off, "[Tri] key");
    font.chainprintf(gpu(), {{.x = 6, .y = int16_t(6 + 2 * c_lineHeight)}}, m_lightOn[1] ? c_on : c_off, "[Cir] fill");
    font.chainprintf(gpu(), {{.x = 6, .y = int16_t(6 + 3 * c_lineHeight)}}, m_lightOn[2] ? c_on : c_off, "[Cro] rim");

    m_orbit += kOrbitPerFrame;
}

int main() { return g_life3d.run(); }
