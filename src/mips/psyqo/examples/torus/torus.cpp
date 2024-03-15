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

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/ordering-table.hh"
#include "psyqo/primitives/lines.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/primitives/rectangles.hh"
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/vector.hh"

#define USE_GTE_FOR_GENERATION 1
#define USE_GTE_FOR_APPROXIMATION 1
#define USE_GTE_FOR_RENDERING 1

using namespace psyqo::fixed_point_literals;
using namespace psyqo::timer_literals;
using namespace psyqo::trig_literals;

namespace {

__attribute__((section(".scratchpad"))) psyqo::Color s_lut[256];

constexpr psyqo::Color c_backgroundColor{{.r = 0x34, .g = 0x58, .b = 0x6c}};

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

template <size_t Circles, size_t Points>
struct TorusTemplate {
    static constexpr size_t C = Circles;
    static constexpr size_t P = Points;
    static constexpr size_t Count = Circles * Points;
    eastl::array<psyqo::GTE::PackedVec3, Circles * Points> vertices;
    eastl::array<psyqo::GTE::PackedVec3, Circles * Points> normals;
    static void getVerticesForFace(unsigned index, unsigned& v1, unsigned& v2, unsigned& v3, unsigned& v4) {
        unsigned circle = index / Points;
        unsigned point = index % Points;
        v1 = circle * Points + point;
        v2 = circle * Points + ((point + 1) % Points);
        v3 = ((circle + 1) % Circles) * Points + point;
        v4 = ((circle + 1) % Circles) * Points + ((point + 1) % Points);
    }
    static void getFacesForVertex(unsigned index, unsigned& f1, unsigned& f2, unsigned& f3, unsigned& f4) {
        int circle = index / Points;
        int point = index % Points;
        f1 = ((circle - 1) % Circles) * Points + ((point - 1) % Points);
        f2 = ((circle - 1) % Circles) * Points + point;
        f3 = circle * Points + ((point - 1) % Points);
        f4 = circle * Points + point;
    }
    void computeNormals() {
#if USE_GTE_FOR_GENERATION
        psyqo::Vec3 cp;
        psyqo::Vec3 sq;
#endif
        // First, compute all normals for all the faces
        eastl::array<psyqo::Vec3, Count> faceNormals;
        for (unsigned index = 0; index < Count; index++) {
            unsigned a, b, c, d;
            getVerticesForFace(index, a, b, c, d);
            psyqo::Vec3 va = psyqo::Vec3(vertices[a]);
            psyqo::Vec3 vb = psyqo::Vec3(vertices[b]);
            psyqo::Vec3 vc = psyqo::Vec3(vertices[c]);
            psyqo::Vec3 s = vb - va;
            psyqo::Vec3 t = vc - va;
#if USE_GTE_FOR_GENERATION
            psyqo::GTE::write<psyqo::GTE::Register::R11R12, psyqo::GTE::Unsafe>(s.x.value);
            psyqo::GTE::write<psyqo::GTE::Register::R22R23, psyqo::GTE::Unsafe>(s.y.value);
            psyqo::GTE::write<psyqo::GTE::Register::R33, psyqo::GTE::Unsafe>(s.z.value);
            psyqo::GTE::write<psyqo::GTE::Register::IR1, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&t.x.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR2, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&t.y.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR3, psyqo::GTE::Safe>(reinterpret_cast<uint32_t*>(&t.z.value));
            psyqo::GTE::Kernels::cp();
            psyqo::GTE::read<psyqo::GTE::PseudoRegister::LV>(&cp);
            psyqo::GTE::Kernels::sqr();
            psyqo::GTE::read<psyqo::GTE::PseudoRegister::LV>(&sq);
            auto square = sq.x + sq.y + sq.z;
#if USE_GTE_FOR_APPROXIMATION
            psyqo::GTE::write<psyqo::GTE::Register::LZCS, psyqo::GTE::Unsafe>(square.raw());
            auto approx = 1 << (psyqo::GTE::readRaw<psyqo::GTE::Register::LZCR>() - 9);
            auto approxFP = psyqo::FixedPoint<>(approx, psyqo::FixedPoint<>::RAW);
            auto len = psyqo::SoftMath::inverseSquareRoot(square, approxFP);
#else
            auto len = psyqo::SoftMath::inverseSquareRoot(square);
#endif
            cp.x *= len;
            cp.y *= len;
            cp.z *= len;
#else
            auto cp = psyqo::SoftMath::crossProductVec3(&s, &t);
            psyqo::SoftMath::normalizeVec3(&cp);
#endif
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
#if USE_GTE_FOR_GENERATION
            psyqo::GTE::write<psyqo::GTE::Register::IR1, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&n.x.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR2, psyqo::GTE::Unsafe>(reinterpret_cast<uint32_t*>(&n.y.value));
            psyqo::GTE::write<psyqo::GTE::Register::IR3, psyqo::GTE::Safe>(reinterpret_cast<uint32_t*>(&n.z.value));
            psyqo::GTE::Kernels::sqr();
            psyqo::GTE::read<psyqo::GTE::PseudoRegister::LV>(&sq);
            auto square = sq.x + sq.y + sq.z;
#if USE_GTE_FOR_APPROXIMATION
            psyqo::GTE::write<psyqo::GTE::Register::LZCS, psyqo::GTE::Unsafe>(square.raw());
            auto approx = 1 << (psyqo::GTE::readRaw<psyqo::GTE::Register::LZCR>() - 9);
            auto approxFP = psyqo::FixedPoint<>(approx, psyqo::FixedPoint<>::RAW);
            auto len = psyqo::SoftMath::inverseSquareRoot(square, approxFP);
#else
            auto len = psyqo::SoftMath::inverseSquareRoot(square);
#endif
            n.x *= len;
            n.y *= len;
            n.z *= len;
#else
            psyqo::SoftMath::normalizeVec3(&n);
#endif
            normals[index] = psyqo::GTE::PackedVec3(n);
        }
    }
};

class TorusScene final : public psyqo::Scene {
  public:
    static constexpr size_t Count = 1;
    TorusScene() {
        __builtin_memcpy(s_lut, m_lut1, sizeof(m_lut1));
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
        for (auto& quad : m_quadsShadow.primitives) {
            quad.setColor({.r = 0x08, .g = 0x12, .b = 0x20});
        }
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
        psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
        psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
        psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(60000);
        psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(200);
        psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
        psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());
    }
    typedef TorusTemplate<32, 16> Torus;
    eastl::array<Torus, Count> m_tori;
    eastl::array<psyqo::Fragments::SimpleFragment<psyqo::Prim::GouraudTexturedQuad>, Torus::Count> m_quads[2];
    psyqo::Fragments::FixedFragment<psyqo::Prim::Quad, Torus::Count> m_quadsShadow;
    struct ClutUpload {
        psyqo::Prim::FastFill fill;
        psyqo::Prim::VRAMUpload upload;
        uint32_t data[4];
        psyqo::Prim::FlushCache flushCache;
    };
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_clears[2];
    psyqo::Fragments::SimpleFragment<ClutUpload> m_clutUpload[4];
    psyqo::OrderingTable<4096> m_ots[2];
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
    void generateTorus(unsigned torusIndex) {
        constexpr psyqo::Angle incrementOutside = 2.0_pi / Torus::C;
        constexpr psyqo::Angle incrementInside = 2.0_pi / Torus::P;
        constexpr psyqo::Angle rippleIncrement = 1.0_pi / Count;
        psyqo::Angle ripple = rippleIncrement * torusIndex;
        auto& torus = m_tori[torusIndex];
        ramsyscall_printf("Generating torus %u\n", torusIndex);

        auto amplitude = torusDemo.m_trig.sin(ripple) * 0.8_fp;
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
#if USE_GTE_FOR_GENERATION
                psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(v);
                psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
                torus.vertices[index++] = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
#else
                psyqo::SoftMath::matrixVecMul3(&rot, &v, &v);
                torus.vertices[index++] = psyqo::GTE::PackedVec3(v);
#endif
            }
        }
        torus.computeNormals();
    }
};

TorusScene torusScene;

class TorusGeneratorScene final : public psyqo::Scene {
    void frame() override;
    unsigned m_generationFrame = 0;
    uint32_t m_startTimestamp = 0;
    struct ProgressBar {
        psyqo::Prim::PolyLine<4> line;
        psyqo::Prim::Rectangle rect;
    } m_progressBar;
    uint8_t computePixel(uint8_t x, uint8_t y);

  public:
    TorusGeneratorScene() {
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

uint8_t TorusGeneratorScene::computePixel(uint8_t x_, uint8_t y_) {
    const auto& trig = torusDemo.m_trig;
    psyqo::Angle x(x_ * 8, psyqo::Angle::RAW);
    psyqo::Angle y(y_ * 8, psyqo::Angle::RAW);
    auto v = trig.sin(x) + 0.8_fp * trig.sin(x * 2) + 0.3_fp * trig.cos(x * 3) * trig.sin(x * 5) + trig.sin(y * 2) +
             0.7_fp * trig.cos(y * 8) + 0.2_fp * trig.sin(y * 4) * trig.cos(y * 11) * trig.sin(x * 8);
    return eastl::clamp(v.integer<32>() + 128, int32_t(0), int32_t(255));
}

void TorusGeneratorScene::frame() {
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
        psyqo::Rect region = {.pos = {{.x = 0, .y = 511}}, .size = {{.w = 256, .h = 1}}};
        psyqo::Prim::VRAMUpload upload;
        upload.region = region;
        gpu().sendPrimitive(upload);
        for (unsigned i = 0; i < 128; i++) {
            gpu().sendRaw(0xbdefbdef);
        }
        upload.region = region;
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
    m_progressBar.rect.size.w = int16_t(m_generationFrame);
    gpu().sendPrimitive(m_progressBar);
}

void TorusScene::frame() {
    uint32_t beginFrame = gpu().now();
    auto currentFrameCounter = gpu().getFrameCount();
    auto frameDiff = currentFrameCounter - torusScene.m_lastFrameCounter;
    if (frameDiff == 0) {
        return;
    }
    torusScene.m_lastFrameCounter = currentFrameCounter;
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
    auto transform = psyqo::SoftMath::generateRotationMatrix33(m_angleX, psyqo::SoftMath::Axis::X, &torusDemo.m_trig);
    auto rot = psyqo::SoftMath::generateRotationMatrix33(m_angleY, psyqo::SoftMath::Axis::Y, &torusDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::SoftMath::generateRotationMatrix33(&rot, m_angleZ, psyqo::SoftMath::Axis::Z, &torusDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);
#if USE_GTE_FOR_RENDERING
    psyqo::GTE::Long sz;
#endif
    eastl::array<psyqo::Vertex, Torus::Count> projected;
    eastl::array<uint8_t, Torus::Count> zNormal;
    eastl::array<int32_t, Torus::Count> zValues;
#if USE_GTE_FOR_RENDERING
    unsigned i = 0;
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
#else
    for (unsigned i = 0; i < Torus::Count; i++) {
        psyqo::Vec3 v = m_tori[animationIndex].vertices[i];
        psyqo::SoftMath::matrixVecMul3(&transform, &v, &v);
        zValues[i] = v.z.raw();
        v.z += 32.0_fp;
        psyqo::Vec2 p;
        psyqo::SoftMath::project(&v, 24.0_fp, &p);
        projected[i] = psyqo::Vertex{{.x = int16_t(p.x.integer<16>() + 160), .y = int16_t(p.y.integer<16>() + 120)}};
        v = m_tori[animationIndex].normals[i];
        int32_t z = (-psyqo::SoftMath::matrixVecMul3z(&transform, &v)).integer<256>() - 1;
        zNormal[i] = eastl::clamp(z, int32_t(0), int32_t(255));
    }
#endif
    auto parity = gpu().getParity();
    auto& quads = m_quads[parity];
    auto& ot = m_ots[parity];
    const psyqo::Color* lut = s_lut;
    for (unsigned index = 0; index < Torus::Count; index++) {
        unsigned a, b, c, d;
        Torus::getVerticesForFace(index, a, b, c, d);
        auto pA = projected[a];
        auto pB = projected[b];
        auto pC = projected[c];
#if USE_GTE_FOR_RENDERING
        psyqo::GTE::write<psyqo::GTE::Register::SXY0, psyqo::GTE::Unsafe>(pA.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY1, psyqo::GTE::Unsafe>(pB.packed);
        psyqo::GTE::write<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>(pC.packed);
        psyqo::GTE::Kernels::nclip();
        int32_t dot = psyqo::GTE::readRaw<psyqo::GTE::Register::MAC0, psyqo::GTE::Safe>();
#else
        int32_t dot = int32_t(pB.x - pA.x) * int32_t(pC.y - pA.y) - int32_t(pB.y - pA.y) * int32_t(pC.x - pA.x);
#endif
        if (dot > 0) {
            continue;
        }
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
#if USE_GTE_FOR_RENDERING
        z -= 140000;
#else
        z += 76500;
#endif
        prim.setColorA(lut[a]);
        prim.setColorB(lut[b]);
        prim.setColorC(lut[c]);
        prim.setColorD(lut[d]);
        ot.insert(quads[index], z >> 5);
    }
    uint8_t clutCounter = m_clutCounter;
    clutCounter += frameDiff;
    m_clutCounter = clutCounter;
    auto& clutUpload = m_clutUpload[(clutCounter & 1) * 2 + parity];
    clutUpload.primitive.upload.region.pos.x = 256 - clutCounter;
    auto& clear = m_clears[parity];
    gpu().getNextClear(clear.primitive, c_backgroundColor);
    gpu().chain(clear);
    gpu().chain(clutUpload);
    gpu().chain(ot);
    torusDemo.m_font.chainprintf(gpu(), {{.x = 2, .y = 2}}, {{.r = 0xff, .g = 0xff, .b = 0xff}}, "FPS: %i",
                                 gpu().getRefreshRate() / frameDiff);
    gpu().pumpCallbacks();
    uint32_t endFrame = gpu().now();
    uint32_t spent = endFrame - beginFrame;
    ramsyscall_printf("Frame took %ius to complete\n", spent);
}

int main() { return torusDemo.run(); }
