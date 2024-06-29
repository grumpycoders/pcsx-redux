/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include <EASTL/algorithm.h>

#include "common/hardware/dma.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/font.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/ordering-table.hh"
#include "psyqo/primitives/control.hh"
#include "psyqo/primitives/lines.hh"
#include "psyqo/primitives/misc.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/primitives/rectangles.hh"
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/vector.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::timer_literals;
using namespace psyqo::trig_literals;

namespace {

// We're going to use the scratchpad to store the color lookup tables.
__attribute__((section(".scratchpad"))) psyqo::Color s_lut[256];

constexpr psyqo::Color c_backgroundColor{{.r = 0x34, .g = 0x58, .b = 0x6c}};

// This is for debugging purposes only.
template <typename T>
void printVec(const T& v) {
    ramsyscall_printf("x: ");
    v.x.print([](char c) { syscall_putchar(c); });
    ramsyscall_printf(", y: ");
    v.y.print([](char c) { syscall_putchar(c); });
    ramsyscall_printf(", z: ");
    v.z.print([](char c) { syscall_putchar(c); });
    syscall_putchar('\n');
}

class TorusDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<2> m_font;
    psyqo::Trig<> m_trig;
    psyqo::SimplePad m_input;
};

TorusDemo torusDemo;

// Our torus is going to be a template with a fixed number of circles and points.
template <size_t Circles, size_t Points>
struct TorusTemplate {
    static constexpr size_t C = Circles;
    static constexpr size_t P = Points;
    // Conveniently, due to the shape of a torus, the number of total vertices is the same as the number of faces.
    static constexpr size_t Count = Circles * Points;
    // For each torii, we're going to store the vertices and the normals. We use the PackedVec3 type to store the
    // data, which are fixed point 4.12 numbers. This limits us to a maximum of 8.0 in each direction, which is
    // totally fine for normals, and for the vertices, our torii will be roughly 7 units in radius maximum.
    // This saves us a lot of memory, as we only need 6 bytes per PackedVec3, instead of 12 bytes for a Vec3.
    eastl::array<psyqo::GTE::PackedVec3, Count> vertices;
    eastl::array<psyqo::GTE::PackedVec3, Count> normals;
    // Looking up the vertices for a face is easy. The vertices are stored in a linear grid, so we can just look
    // up the vertices for the face by looking up the vertices for the corners of the face.
    static void getVerticesForFace(unsigned index, unsigned& v1, unsigned& v2, unsigned& v3, unsigned& v4) {
        unsigned circle = index / Points;
        unsigned point = index % Points;
        v1 = circle * Points + point;
        v2 = circle * Points + ((point + 1) % Points);
        v3 = ((circle + 1) % Circles) * Points + point;
        v4 = ((circle + 1) % Circles) * Points + ((point + 1) % Points);
    }
    // Similarly, we can easily look up the four faces adjacent to a vertex.
    static void getFacesForVertex(unsigned index, unsigned& f1, unsigned& f2, unsigned& f3, unsigned& f4) {
        int circle = index / Points;
        int point = index % Points;
        f1 = ((circle - 1) % Circles) * Points + ((point - 1) % Points);
        f2 = ((circle - 1) % Circles) * Points + point;
        f3 = circle * Points + ((point - 1) % Points);
        f4 = circle * Points + point;
    }
    // Theoretically, the normals of a torus are easy to compute. But our torii have some animated ripples, so we're
    // going to compute the normals at boot time. This is a bit more expensive, but it's a one-time cost.
    void computeNormals() {
        psyqo::Vec3 cp;
        psyqo::Vec3 sq;
        // First, compute all normals for all the faces
        eastl::array<psyqo::Vec3, Count> faceNormals;
        for (unsigned index = 0; index < Count; index++) {
            unsigned a, b, c, d;
            getVerticesForFace(index, a, b, c, d);
            // We only need two vectors to compute the normal of a face. We're going to use the first three
            // vertices of the face.
            psyqo::Vec3 va = psyqo::Vec3(vertices[a]);
            psyqo::Vec3 vb = psyqo::Vec3(vertices[b]);
            psyqo::Vec3 vc = psyqo::Vec3(vertices[c]);
            psyqo::Vec3 s = vb - va;
            psyqo::Vec3 t = vc - va;
            // The cross product operation uses the diagonal of the rotation matrix (R11, R22, R33) for the first
            // vector, and the IR registers for the second vector.
            psyqo::GTE::write<psyqo::GTE::Register::R11R12, psyqo::GTE::Unsafe>(s.x.value);
            psyqo::GTE::write<psyqo::GTE::Register::R22R23, psyqo::GTE::Unsafe>(s.y.value);
            psyqo::GTE::write<psyqo::GTE::Register::R33, psyqo::GTE::Unsafe>(s.z.value);
            psyqo::GTE::write<psyqo::GTE::Register::IR1, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&t.x.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR2, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&t.y.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR3, psyqo::GTE::Safe>(reinterpret_cast<uint32_t*>(&t.z.value));
            psyqo::GTE::Kernels::cp();
            // The result is stored in the LV register, so first we simply read it.
            psyqo::GTE::read<psyqo::GTE::PseudoRegister::LV>(&cp);
            // Then we square LV to get the square of the length of the normal.
            psyqo::GTE::Kernels::sqr();
            psyqo::GTE::read<psyqo::GTE::PseudoRegister::LV>(&sq);
            // We still need to add the three components of the square.
            auto square = sq.x + sq.y + sq.z;
            // Finally, we compute the square root of the square of the length of the normal.
            // A fast method to compute the square root is to use the inverse square root. And we're going to use
            // log2 of the square to get an approximation of the square root, before refining it with the inverse
            // square root method.
            psyqo::GTE::write<psyqo::GTE::Register::LZCS, psyqo::GTE::Unsafe>(square.raw());
            auto approx = 1 << (psyqo::GTE::readRaw<psyqo::GTE::Register::LZCR>() - 9);
            auto approxFP = psyqo::FixedPoint<>(approx, psyqo::FixedPoint<>::RAW);
            auto len = psyqo::SoftMath::inverseSquareRoot(square, approxFP);
            // We multiply the normal by the inverse square root of the square of the length of the normal in order to
            // normalize it.
            cp.x *= len;
            cp.y *= len;
            cp.z *= len;
            faceNormals[index] = cp;
        }

        // Then, average all 4 normals for each vertex
        for (unsigned index = 0; index < Count; index++) {
            unsigned a, b, c, d;
            getFacesForVertex(index, a, b, c, d);
            psyqo::Vec3 na = faceNormals[a];
            psyqo::Vec3 nb = faceNormals[b];
            psyqo::Vec3 nc = faceNormals[c];
            psyqo::Vec3 nd = faceNormals[d];
            psyqo::Vec3 n = na + nb + nc + nd;
            // Technically, we could re-compute the square of the length of the normal and normalize it again, but
            // it's not necessary since we just added 4 normalized vectors, meaning we can simply normalize the
            // result by dividing it by 4.
            n.x /= 4;
            n.y /= 4;
            n.z /= 4;
            normals[index] = psyqo::GTE::PackedVec3(n);
        }
    }
};

// This is the scene that will display the torus animation.
class TorusScene final : public psyqo::Scene {
  public:
    static constexpr size_t Count = 256;
    TorusScene() {
        // Make sure the scratchpad contains our first LUT.
        __builtin_memcpy(s_lut, m_lut1, sizeof(m_lut1));
        // Pre-fill the platform quads.
        for (auto& platformQuads : m_platformQuads) {
            // The platform is a 3x3 grid of quads. We just need to fill the UV coordinates and the TPage attributes,
            // as they will never change throughout the demo. We could also pre-fill the X and Y coordinates, but we
            // don't want to use the GTE at this point. Also maybe we want to move the platform later.
            for (unsigned v = 0; v < 3; v++) {
                for (unsigned u = 0; u < 3; u++) {
                    auto& quad = platformQuads.primitive[u * 3 + v];
                    auto u0 = u * 85;
                    auto v0 = v * 85;
                    auto u1 = (u + 1) * 85 - 1;
                    auto v1 = (v + 1) * 85 - 1;
                    quad.uvA.u = v0;
                    quad.uvA.v = u0;
                    quad.uvB.u = v1;
                    quad.uvB.v = u0;
                    quad.uvC.u = v0;
                    quad.uvC.v = u1;
                    quad.uvD.u = v1;
                    quad.uvD.v = u1;
                    quad.tpage.setPageX(12).setPageY(0).enableDisplayArea().setDithering(false).set(
                        psyqo::Prim::TPageAttr::Tex16Bits);
                }
            }
        }
        // Pre-fill the quads to display the torus. The UV coordinates will always be the same. The color
        // and X and Y coordinates will be computed and set at runtime.
        for (auto& quads : m_quads) {
            unsigned incrementU = 4 * 256 / Torus::C;
            unsigned incrementV = 256 / Torus::P;
            for (unsigned u = 0; u < Torus::C; u++) {
                for (unsigned v = 0; v < Torus::P; v++) {
                    auto& prim = quads[u * Torus::P + v].primitive;
                    prim.uvA.u = u * incrementU;
                    prim.uvA.v = v * incrementV;
                    prim.uvB.u = u * incrementU;
                    prim.uvB.v = (v + 1) * incrementV - 1;
                    prim.uvC.u = (u + 1) * incrementU - 1;
                    prim.uvC.v = v * incrementV;
                    prim.uvD.u = (u + 1) * incrementU - 1;
                    prim.uvD.v = (v + 1) * incrementV - 1;
                    prim.clutIndex = {{.x = 0, .y = 511}};
                    prim.tpage.setPageX(13).setPageY(1).enableDisplayArea().setDithering(true).set(
                        psyqo::Prim::TPageAttr::Tex8Bits);
                }
            }
        }
        // Next up is pre-filling the shadow texture off-screen rendering. We're going to use a 256x256 texture
        // located at (768, 0) to (1024, 256). We're going to fill it with a white color, and then draw some
        // quads on it. The quads will be colored dark blue.
        m_shadowTexture.prologue.scissor.start = {{.x = 768, .y = 0}};
        m_shadowTexture.prologue.scissor.end = {{.x = 1024, .y = 256}};
        m_shadowTexture.prologue.scissor.offset = {{.x = 768, .y = 0}};
        m_shadowTexture.prologue.fill.setColor({.r = 0xff, .g = 0xff, .b = 0xff});
        m_shadowTexture.prologue.fill.rect = {.pos = {{.x = 768, .y = 0}}, .size = {{.w = 256, .h = 256}}};
        for (auto& quad : m_shadowTexture.primitives) {
            quad.setColor({.r = 0x08, .g = 0x12, .b = 0x20});
        }
        // And finally, we're going to pre-fill the CLUT upload primitives. There's only four possible
        // combinations of CLUTs, so we're going to pre-fill all four of them, selecting the proper one
        // at runtime. The location of the CLUTs is at (0, 511), and what we're doing here is patching
        // the existing CLUT with the chunk of animation we need.
        unsigned index = 0;
        for (auto& clutUpload : m_clutUpload) {
            auto& prim = clutUpload.primitive;
            prim.fill.setColor({.r = 0x80, .g = 0x80, .b = 0x80});
            prim.fill.rect = {.pos = {{.x = 0, .y = 511}}, .size = {{.w = 256, .h = 1}}};
            prim.upload.region = {.pos = {{.x = 0, .y = 511}}, .size = {{.w = 8, .h = 1}}};
            switch (index) {
                case 0:
                    prim.data[0] = 0xce73bdef;
                    prim.data[1] = 0xef7bdef7;
                    prim.data[2] = 0xef7bffff;
                    prim.data[3] = 0xce73def7;
                    break;
                case 1:
                    prim.data[0] = 0xdef7ce73;
                    prim.data[1] = 0xffffef7b;
                    prim.data[2] = 0xdef7ef7b;
                    prim.data[3] = 0xbdefce73;
                    break;
            }
            index ^= 1;
        }
    }

  private:
    void frame() override;
    void start(StartReason reason) override {
        // The generator finished, our scene starts. We set the proper context.
        m_lastFrameCounter = gpu().getFrameCount();
        torusDemo.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
            if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
            if (event.button == psyqo::SimplePad::Button::Triangle) {
                m_lutIndex = (m_lutIndex + 1) % 3;
            }
            if (event.button == psyqo::SimplePad::Button::Cross) {
                m_lutInverted = !m_lutInverted;
            }
            const psyqo::Color* lut = nullptr;
            switch (m_lutIndex) {
                case 0:
                    lut = m_lut1;
                    break;
                case 1:
                    lut = m_lut2;
                    break;
                case 2:
                    lut = m_lut3;
                    break;
            }
            if (m_lutInverted) {
                for (unsigned i = 0; i < 256; i++) {
                    s_lut[i] = lut[255 - i];
                }
            } else {
                __builtin_memcpy(s_lut, lut, sizeof(m_lut1));
            }
        });
        // These will never change.
        psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
        psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
    }

    // This array will represent our biggest memory chunk. It's going to be used to store the torii
    // with all of their vertices and normals. It goes to 1'572'864 bytes, which will get filled up
    // by the generator.
    typedef TorusTemplate<32, 16> Torus;
    eastl::array<Torus, Count> m_tori;

    // After this, we reserve memory for all of the possible draw calls.
    // First, we store the commands for the off-screen rendering of the shadow texture. There's not going
    // to be any double bufferingn on them, so we only need one set of commands.
    struct ShadowTexturePrologue {
        psyqo::Prim::Scissor scissor;
        psyqo::Prim::FastFill fill;
    };
    psyqo::Fragments::FixedFragmentWithPrologue<ShadowTexturePrologue, psyqo::Prim::Quad, Torus::Count> m_shadowTexture;
    // Then we store all the commands which will be chained together to draw the rest of the scene. We store
    // them in the order they will be sent, purely for readability.
    // Our scene starts with a fast fill of the entire screen, to clear it.
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_startScene[2];
    // Then we patch the CLUT with the proper animation. There are only four possible combinations of CLUTs patches,
    // so we don't even need to double buffer them. They'll be naturally used in sequence, frame by frame. The only
    // case where this would fail is if the frame rate goes low enough that we're skipping 3 frames, but that's not
    // going to happen.
    struct ClutUpload {
        psyqo::Prim::FastFill fill;
        psyqo::Prim::VRAMUpload upload;
        uint32_t data[4];
        psyqo::Prim::FlushCache flushCache;
    };
    psyqo::Fragments::SimpleFragment<ClutUpload> m_clutUpload[4];
    // Then we draw the platform. The platform is a 3x3 grid of quads. Technically as of now, the platform is
    // static, but we could animate it later, so we can keep double buffering it.
    psyqo::Fragments::SimpleFragment<eastl::array<psyqo::Prim::TexturedQuad, 9>> m_platformQuads[2];
    // Finally, we have the draw calls for our torus. Note that this is an array of fragments, instead of
    // being a fragment composed of an array, because we're going to chain them together in a specific order.
    // In other words, the other fragments are simple contiguous memory blocks sent in one go, while this one
    // is a bunch of memory blocks that we'll chain together into the ordering table, working as a sort of
    // arena allocator. And as usual, we're going to double buffer them. This is a significant memory chunk,
    // of roughly 54kB.
    eastl::array<psyqo::Fragments::SimpleFragment<psyqo::Prim::GouraudTexturedQuad>, Torus::Count> m_quads[2];

    // The last needed piece we need is the ordering table. We're going to use two of them, for double buffering.
    psyqo::OrderingTable<4096> m_ots[2];

    // The rest of our variables are normal state keeping.
    uint32_t m_lastFrameCounter;
    psyqo::Angle m_angleX = 0.0_pi;
    psyqo::Angle m_angleY = 0.0_pi;
    psyqo::Angle m_angleZ = 0.0_pi;
    unsigned m_animationCounter = 0;

#include "presets.hh"

    unsigned m_lutIndex = 0;
    bool m_lutInverted = false;
    uint8_t m_clutCounter = 0;

  public:
    // The helper function to generate one torus. This is a fairly normal torus generation function, with the
    // exception that we're adding a ripple effect to the torus. The depth of the ripples is determined by the
    // index of the torus.
    void generateTorus(unsigned torusIndex) {
        constexpr psyqo::Angle incrementOutside = 2.0_pi / Torus::C;
        constexpr psyqo::Angle incrementInside = 2.0_pi / Torus::P;
        constexpr psyqo::Angle rippleIncrement = 1.0_pi / Count;
        psyqo::Angle ripple = rippleIncrement * torusIndex;
        auto& torus = m_tori[torusIndex];
        ramsyscall_printf("Generating torus %u\n", torusIndex);

        auto amplitude = torusDemo.m_trig.sin(ripple) * 0.6_fp;
        unsigned index = 0;
        for (psyqo::Angle outside = 0; outside < 2.0_pi; outside += incrementOutside) {
            auto rot = psyqo::SoftMath::generateRotationMatrix33(outside, psyqo::SoftMath::Axis::Z, &torusDemo.m_trig);
            psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(rot);
            psyqo::FixedPoint<> rippleAmplitude = amplitude * torusDemo.m_trig.sin(outside * 5 + ripple * 8) + 1.5_fp;
            for (psyqo::Angle inside = 0; inside < 2.0_pi; inside += incrementInside) {
                psyqo::Vec3 v;
                auto c = torusDemo.m_trig.cos(inside);
                auto s = torusDemo.m_trig.sin(inside);
                v.x = 0.0_fp;
                v.y = c * rippleAmplitude + 4.0_fp;
                v.z = s * rippleAmplitude;
                psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(v);
                psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
                torus.vertices[index++] = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
            }
        }
        torus.computeNormals();
    }
};

TorusScene torusScene;

// This is the scene that will generate the torus animation. It'll be a simple progress bar.
// It's also the first scene that will be pushed.
class TorusGeneratorScene final : public psyqo::Scene {
    void frame() override;
    unsigned m_generationFrame = 0;
    uint32_t m_startTimestamp = 0;
    // Our generator scene won't try to double buffer, so we only need one set of primitives.
    struct ProgressBar {
        psyqo::Prim::PolyLine<4> line;
        psyqo::Prim::Rectangle rect;
    } m_progressBar;
    uint8_t computePixel(uint8_t x, uint8_t y);

  public:
    TorusGeneratorScene() {
        // Preparing the progress bar drawing calls.
        m_progressBar.line.setColor({{.r = 255, .g = 255, .b = 255}});
        m_progressBar.line.points[0] = {{.x = 30, .y = 118}};
        m_progressBar.line.points[1] = {{.x = 30, .y = 138}};
        m_progressBar.line.points[2] = {{.x = 290, .y = 138}};
        m_progressBar.line.points[3] = {{.x = 290, .y = 118}};
        m_progressBar.line.points[4] = {{.x = 30, .y = 118}};
        m_progressBar.rect.position = {{.x = 32, .y = 120}};
        m_progressBar.rect.size = {{.w = 0, .h = 17}};
        m_progressBar.rect.setColor({{.r = 255, .g = 255, .b = 255}});
    }
};

TorusGeneratorScene torusGeneratorScene;

}  // namespace

void TorusDemo::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void TorusDemo::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&torusGeneratorScene);
}

// See the proctex example for more details on this.
uint8_t TorusGeneratorScene::computePixel(uint8_t x_, uint8_t y_) {
    const auto& trig = torusDemo.m_trig;
    psyqo::Angle x(x_ * 8, psyqo::Angle::RAW);
    psyqo::Angle y(y_ * 8, psyqo::Angle::RAW);
    auto v = trig.sin(x) + 0.8_fp * trig.sin(x * 2) + 0.3_fp * trig.cos(x * 3) * trig.sin(x * 5) + trig.sin(y * 2) +
             0.7_fp * trig.cos(y * 8) + 0.2_fp * trig.sin(y * 4) * trig.cos(y * 11) * trig.sin(x * 8);
    return eastl::clamp(v.integer<32>() + 128, int32_t(0), int32_t(255));
}

void TorusGeneratorScene::frame() {
    // Each frame of the generator will be used to generate exactly one torus, and one line of our procedural texture.
    // We're going to generate 256 torii and 256 lines of the texture, so this works out perfectly. The current
    // generation code takes about 7 seconds to generate all the torii and the texture, and we're generating 256
    // frames, so roughly 30ms per frame. This means that this screen will run at 30fps, which is more than enough.
    if (m_generationFrame < eastl::max(TorusScene::Count, size_t(256))) {
        if (m_generationFrame == 0) {
            m_startTimestamp = gpu().now();
        }
        if (m_generationFrame < TorusScene::Count) {
            torusScene.generateTorus(m_generationFrame);
        }
        if (m_generationFrame < 256) {
            psyqo::Rect region = {.pos = {{.x = 830, .y = int16_t(m_generationFrame + 256)}},
                                  .size = {{.w = 128, .h = 1}}};
            psyqo::Prim::VRAMUpload upload;
            upload.region = region;
            gpu().sendPrimitive(upload);
            for (unsigned x = 0; x < 256; x += 4) {
                uint32_t d = 0;
                for (unsigned i = 0; i < 4; i++) {
                    uint32_t c = computePixel(x + i, m_generationFrame);
                    d >>= 8;
                    c <<= 24;
                    d |= c;
                }
                gpu().sendRaw(d);
            }
        }
    } else {
        // Once we're all done, we're going to upload a solid CLUT, which will be then patched with the animation.
        psyqo::Rect region = {.pos = {{.x = 0, .y = 511}}, .size = {{.w = 256, .h = 1}}};
        psyqo::Prim::VRAMUpload upload;
        upload.region = region;
        gpu().sendPrimitive(upload);
        for (unsigned i = 0; i < 128; i++) {
            gpu().sendRaw(0xbdefbdef);
        }
        psyqo::Prim::FlushCache fc;
        gpu().sendPrimitive(fc);
        pushScene(&torusScene);
    }
    m_generationFrame++;
    uint32_t elapsed = (gpu().now() - m_startTimestamp) / 1000;
    int32_t eta = (elapsed * eastl::max(TorusScene::Count, size_t(256))) / m_generationFrame - elapsed;
    gpu().clear(c_backgroundColor);
    torusDemo.m_font.print(gpu(), "Generating animation...", {{.x = 60, .y = 80}}, {{.r = 255, .g = 255, .b = 255}});
    torusDemo.m_font.printf(gpu(), {{.x = 60, .y = 160}}, {{.r = 255, .g = 255, .b = 255}}, "Elapsed: %us, ETA: %us",
                            elapsed / 1000, eastl::max(eta, int32_t(0)) / 1000);
    // This is the only dynamic part of the progress bar, so that's the only write to our draw calls we're doing.
    m_progressBar.rect.size.w = int16_t(m_generationFrame);
    gpu().sendPrimitive(m_progressBar);
}

// Last but not least, the main loop of the demo. A lot of work happens for each frame, but it's all
// done under 10ms, which is more than good enough for 60fps, with room to spare.
void TorusScene::frame() {
    // We're still going to do adaptive frame rate, so we're going to look at the number of frames that have passed
    // since the last frame, and we're going to adjust the animation accordingly.
    uint32_t beginFrame = gpu().now();
    auto currentFrameCounter = gpu().getFrameCount();
    auto frameDiff = currentFrameCounter - torusScene.m_lastFrameCounter;
    if (frameDiff == 0) {
        // This shouldn't happen, but, eh.
        return;
    }
    torusScene.m_lastFrameCounter = currentFrameCounter;
    // We're going to update the various animation counters first thing.
    unsigned animationIndex = 0;
    if (m_animationCounter >= 1500) {
        m_animationCounter = 0;
    } else {
        if (m_animationCounter < (m_tori.size() * 2)) {
            animationIndex = m_animationCounter / 2;
        }
        m_animationCounter += frameDiff;
    }
    for (unsigned i = 0; i < frameDiff; i++) {
        m_angleX += 0.001_pi;
        m_angleY += 0.002_pi;
        m_angleZ += 0.003_pi;
    }
    if (m_angleX >= 2.0_pi) {
        m_angleX -= 2.0_pi;
    }
    if (m_angleY >= 2.0_pi) {
        m_angleY -= 2.0_pi;
    }
    if (m_angleZ >= 2.0_pi) {
        m_angleZ -= 2.0_pi;
    }

    // And now we go into the meat of the frame. Generating the transformation matrix here, and uploading it to the GTE.
    // It is relevant to note that at this point, the previous frame may still be sent to the GPU through the DMA chain.
    // These matrix multiplications are done in software, and they're not particularly fast, but it's done only once per
    // frame, so it's not really a problem. The computation could be accelerated using the GTE however, but we're not
    // starving for CPU at this point, so it's all good.
    auto transform = psyqo::SoftMath::generateRotationMatrix33(m_angleX, psyqo::SoftMath::Axis::X, &torusDemo.m_trig);
    auto rot = psyqo::SoftMath::generateRotationMatrix33(m_angleY, psyqo::SoftMath::Axis::Y, &torusDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::SoftMath::generateRotationMatrix33(&rot, m_angleZ, psyqo::SoftMath::Axis::Z, &torusDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);

    // All these will be reused multiple times over the course of the frame.
    psyqo::GTE::Long sz;
    eastl::array<psyqo::Vertex, Torus::Count> projected;
    eastl::array<uint8_t, Torus::Count> zNormal;
    eastl::array<int32_t, Torus::Count> zValues;
    unsigned i = 0;
    const auto parity = gpu().getParity();

    // This phase is to generate the drawcalls for the off-screen rendering of the shadow texture.

    // So we need to adjust the GTE rendering context accordingly. We're going to render the torus with a
    // sort of telephoto lens angle, in a 256x256 destination texture.
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(40000);
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(320);
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(128.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(128.0).raw());

    // We don't need to sort the quads, or try to cull them, as they'll all be mushed together in a single
    // black-ish shadow blob. So we just first have a pass of projecting all of the vertices for our
    // currently selected torus.
    for (; i < Torus::Count - 2; i += 3) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_tori[animationIndex].vertices[i + 0]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_tori[animationIndex].vertices[i + 1]);
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_tori[animationIndex].vertices[i + 2]);
        psyqo::GTE::Kernels::rtpt();
        psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&projected[i + 0].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&projected[i + 1].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i + 2].packed);
    }
    for (; i < Torus::Count; i++) {
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_tori[animationIndex].vertices[i]);
        psyqo::GTE::Kernels::rtps();
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i].packed);
    }

    // Then we simply fill in the primitives buffer of the off-screen render with the projected vertices.
    for (unsigned index = 0; index < Torus::Count; index++) {
        unsigned a, b, c, d;
        Torus::getVerticesForFace(index, a, b, c, d);
        auto pA = projected[a];
        auto pB = projected[b];
        auto pC = projected[c];
        auto pD = projected[d];
        auto& prim = m_shadowTexture.primitives[index];
        prim.pointA = pA;
        prim.pointB = pB;
        prim.pointC = pC;
        prim.pointD = pD;
    }

    // Now we're going to render the rest of the scene, so we adjust the GTE context. Our camera gets a wider
    // angle, and we're going to render to the full screen of 320x240.
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(60000);
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(280);
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());

    // The first piece to render is the platform with the shadow texture. We might want to animate the platform
    // in the future, but for now it's static, so we just upload the identity matrix to the GTE's rotation register.
    static constexpr psyqo::Matrix33 identity = {{
        {1.0_fp, 0.0_fp, 0.0_fp},
        {0.0_fp, 1.0_fp, 0.0_fp},
        {0.0_fp, 0.0_fp, 1.0_fp},
    }};
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(identity);
    i = 0;
    // The platform is a simple 3x3 grid of quads. We're going to project the vertices and then fill in the
    // primitives buffer for it. As noted before, these values will technically never change, but we're going
    // to put this in the main loop still in case we want to animate it later.
    psyqo::Vertex platformVertices[16];
    auto* platformVertex = platformVertices;
    psyqo::FixedPoint<> v = -7.0_fp;
    for (unsigned j = 0; j < 4; j++) {
        psyqo::FixedPoint<> u = -7.0_fp;
        for (unsigned i = 0; i < 4; i++) {
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(psyqo::Vec3(u + 1.70166_fp, 4.39747_fp, v - 0.10009));
            psyqo::GTE::Kernels::rtps();
            psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&platformVertex->packed);
            platformVertex++;
            u += 3.5_fp;
        }
        v += 3.5_fp;
    }
    auto& platformQuads = m_platformQuads[parity];
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = 0; j < 3; j++) {
            auto quad = &platformQuads.primitive[i * 3 + j];
            quad->pointA = platformVertices[(3 - i) * 4 + j];
            quad->pointB = platformVertices[(3 - i) * 4 + j + 1];
            quad->pointC = platformVertices[(2 - i) * 4 + j];
            quad->pointD = platformVertices[(2 - i) * 4 + j + 1];
        }
    }

    // Almost done. Next, we render our torus. We retrieve the previous rotation matrix used to render the off-screen
    // shadow texture, and we multiply it by a 90 degree rotation around the X axis, as the platform is going to be
    // rendered visually underneath the torus. This will make the appearance that everything has been projected
    // properly, but it's all just a visual trick.
    psyqo::SoftMath::generateRotationMatrix33(&rot, 0.5_pi, psyqo::SoftMath::Axis::X, &torusDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);

    // At this point, our background DMA chain has most likely finished. At some point, we want to send
    // the draw calls for the off-screen rendering of the shadow texture, and ensure that we're not just going
    // to idly stall until it's done rendering, so we should send it mid-frame, after some computation has
    // been done, but also while there's still some computation to be done. This spot is as good as any.

    // We're still going to ensure that the previous frame's DMA chain has been done sending.
    gpu().waitChainIdle();

    // And then we're going to send the shadow texture rendering commands. We'll have to stall at the end
    // of our computation to ensure the shadow texture is done rendering, so we keep a boolean on the stack
    // indicating whether the shadow texture has been sent, and it'll toggle during the ISR at the end of
    // the transfer.
    bool shadowSent = false;
    gpu().sendFragment(
        m_shadowTexture,
        [&shadowSent]() {
            shadowSent = true;
            // Since we're going to mutate a stack variable from the ISR, we need to tell our compiler that.
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        psyqo::DMA::FROM_ISR);

    // With this intermission done, we can now proceed to render the torus. We're going to project the vertices and
    // rotate the normals. This loop is a balance between waiting for the GTE to finish projecting the vertices and
    // the CPU doing the rotation of the normals. The GTE is faster, and we technically would be better off
    // doing the rotation in the GTE, but (1) we have a special z-only rotation kernel function, and (2) we're
    // basically pipelining the GTE and the CPU here, for maximum throughput. We'll only use the z value for each
    // normal to compute the light incidence from a light source located at (0, 0, 0).
    for (; i < Torus::Count - 2; i += 3) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_tori[animationIndex].vertices[i + 0]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_tori[animationIndex].vertices[i + 1]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V2>(m_tori[animationIndex].vertices[i + 2]);
        psyqo::Vec3 v0 = m_tori[animationIndex].normals[i + 0];
        psyqo::Vec3 v1 = m_tori[animationIndex].normals[i + 1];
        psyqo::Vec3 v2 = m_tori[animationIndex].normals[i + 2];
        psyqo::GTE::Kernels::rtpt();
        auto sz = -psyqo::SoftMath::matrixVecMul3z(&transform, &v0);
        int32_t z = sz.integer<256>() - 1;
        zNormal[i + 0] = eastl::clamp(z, int32_t(0), int32_t(255));
        sz = -psyqo::SoftMath::matrixVecMul3z(&transform, &v1);
        z = sz.integer<256>() - 1;
        zNormal[i + 1] = eastl::clamp(z, int32_t(0), int32_t(255));
        sz = -psyqo::SoftMath::matrixVecMul3z(&transform, &v2);
        z = sz.integer<256>() - 1;
        zNormal[i + 2] = eastl::clamp(z, int32_t(0), int32_t(255));
        psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&projected[i + 0].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ1>(reinterpret_cast<uint32_t*>(&zValues[i + 0]));
        psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&projected[i + 1].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ2>(reinterpret_cast<uint32_t*>(&zValues[i + 1]));
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i + 2].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ3>(reinterpret_cast<uint32_t*>(&zValues[i + 2]));
    }
    for (; i < Torus::Count; i++) {
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_tori[animationIndex].vertices[i]);
        psyqo::Vec3 v = m_tori[animationIndex].normals[i];
        psyqo::GTE::Kernels::rtps();
        auto sz = -psyqo::SoftMath::matrixVecMul3z(&transform, &v);
        int32_t z = sz.integer<256>() - 1;
        zNormal[i] = eastl::clamp(z, int32_t(0), int32_t(255));
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[i].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SZ3>(reinterpret_cast<uint32_t*>(&zValues[i]));
    }

    // What's left for us to do to render the torus is to adjust the primitive buffer for the torus using the ordering
    // table while culling the back faces using nclip.
    auto& quads = m_quads[parity];
    auto& ot = m_ots[parity];
    const psyqo::Color* lut = s_lut;
    for (unsigned index = 0; index < Torus::Count; index++) {
        unsigned a, b, c, d;
        Torus::getVerticesForFace(index, a, b, c, d);
        auto pA = projected[a];
        auto pB = projected[b];
        auto pC = projected[c];
        psyqo::GTE::write<psyqo::GTE::Register::SXY0, psyqo::GTE::Unsafe>(pA.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY1, psyqo::GTE::Unsafe>(pB.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>(pC.packed);
        psyqo::GTE::Kernels::nclip();
        int32_t dot = psyqo::GTE::readRaw<psyqo::GTE::Register::MAC0, psyqo::GTE::Safe>();
        if (dot > 0) continue;
        // Our quad didn't get culled, so we adjust its 4 points and colors, and insert
        // it into the ordering table.
        auto pD = projected[d];
        auto& prim = quads[index].primitive;
        auto z = zValues[a] + zValues[b] + zValues[c] + zValues[d];
        prim.pointA = pA;
        a = zNormal[a];
        prim.pointB = pB;
        b = zNormal[b];
        prim.pointC = pC;
        c = zNormal[c];
        prim.pointD = pD;
        d = zNormal[d];
        z -= 140000;
        prim.setColorA(lut[a]);
        prim.setColorB(lut[b]);
        prim.setColorC(lut[c]);
        prim.setColorD(lut[d]);
        ot.insert(quads[index], z >> 5);
    }

    // And finally, we need to patch the CLUT for its animation.
    uint8_t clutCounter = m_clutCounter;
    clutCounter += frameDiff;
    m_clutCounter = clutCounter;
    auto& clutUpload = m_clutUpload[(clutCounter & 1) * 2 + parity];
    clutUpload.primitive.upload.region.pos.x = 256 - clutCounter;

    // We're all done, so all that's left for us to do is to chain the draw calls together and finish our frame.
    auto& startScene = m_startScene[parity];
    gpu().getNextClear(startScene.primitive, c_backgroundColor);
    gpu().chain(startScene);
    gpu().chain(clutUpload);
    gpu().chain(platformQuads);
    gpu().chain(ot);

#ifdef MEASURE_PERFORMANCE
    // We can measure and display the performance of the demo, which is useful when optimizing.
    torusDemo.m_font.chainprintf(gpu(), {{.x = 2, .y = 2}}, {{.r = 0xff, .g = 0xff, .b = 0xff}}, "FPS: %i",
                                 gpu().getRefreshRate() / frameDiff);
    // The `now()` function will not return a new value until `pumpCallbacks()` is called, so we need to do that
    // to ensure that we're measuring the time correctly.
    gpu().pumpCallbacks();
    uint32_t endFrame = gpu().now();
    uint32_t spent = endFrame - beginFrame;
    ramsyscall_printf("Frame took %ius to complete\n", spent);
#endif

    // At this point our off-screen rendering of the shadow texture should be done, but we're still going to
    // try stalling for it just in case, as we can't let the DMA chain to begin if there's still another
    // DMA in progress.
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    while (!shadowSent) {
        gpu().pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

int main() { return torusDemo.run(); }
