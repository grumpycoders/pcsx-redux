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

#include <EASTL/array.h>

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/font.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/primitives/rectangles.hh"
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/trigonometry.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

namespace {

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

void printMat(const psyqo::Matrix33& m) {
    for (unsigned i = 0; i < 3; i++) {
        ramsyscall_printf("| ");
        m.vs[i].x.print([](char c) { syscall_putchar(c); });
        ramsyscall_printf(" ");
        m.vs[i].y.print([](char c) { syscall_putchar(c); });
        ramsyscall_printf(" ");
        m.vs[i].z.print([](char c) { syscall_putchar(c); });
        ramsyscall_printf(" |\n");
    }
}

class GTEDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::Trig<> m_trig;
    psyqo::SimplePad m_pad;
};

template <size_t Circles, size_t Points>
struct TorusTemplate {
    static constexpr size_t C = Circles;
    static constexpr size_t P = Points;
    static constexpr size_t Count = Circles * Points;
    eastl::array<psyqo::GTE::PackedVec3, Circles * Points> vertices;
};

class GTEScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;
    void generateTorus();
    psyqo::Angle m_angleX = 0.0_pi;
    psyqo::Angle m_angleY = 0.0_pi;
    psyqo::Angle m_angleZ = 0.0_pi;
    constexpr static psyqo::Angle c_angleXStep = 0.001_pi;
    constexpr static psyqo::Angle c_angleYStep = 0.002_pi;
    constexpr static psyqo::Angle c_angleZStep = 0.003_pi;
    typedef TorusTemplate<32, 16> Torus;
    Torus m_torus;
    int32_t m_trz = 60000;
    uint16_t m_h = 300;
    psyqo::Fragments::FixedFragment<psyqo::Prim::Pixel, Torus::Count> m_pixels;
    bool m_projected = true;
};

// We're instantiating the two objects above right now.
GTEDemo gteDemo;
GTEScene gteScene;

}  // namespace

void GTEDemo::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void GTEDemo::createScene() {
    m_font.uploadSystemFont(gpu());
    m_pad.initialize();
    pushScene(&gteScene);
}

void GTEScene::generateTorus() {
    constexpr psyqo::Angle incrementOutside = 2.0_pi / Torus::C;
    constexpr psyqo::Angle incrementInside = 2.0_pi / Torus::P;
    auto& torus = m_torus;

    unsigned index = 0;
    for (psyqo::Angle outside = 0.0_pi; outside < 2.0_pi; outside += incrementOutside) {
        psyqo::Matrix33 rot =
            psyqo::SoftMath::generateRotationMatrix33(outside, psyqo::SoftMath::Axis::Z, &gteDemo.m_trig);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(rot);
        for (psyqo::Angle inside = 0; inside < 2.0_pi; inside += incrementInside) {
            psyqo::Vec3 v;
            auto c = gteDemo.m_trig.cos(inside);
            auto s = gteDemo.m_trig.sin(inside);
            v.x = 0.0_fp;
            v.y = c + 4.0_fp;
            v.z = s;
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(v);
            psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
            torus.vertices[index] = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
            index++;
        }
    }
}

void GTEScene::start(StartReason reason) {
    gteDemo.m_pad.setOnEvent([this](auto event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Button::Cross) {
            m_projected = !m_projected;
        }
        if (event.button == psyqo::SimplePad::Button::Up) {
            m_trz += 1000;
        }
        if (event.button == psyqo::SimplePad::Button::Down) {
            m_trz -= 1000;
        }
        if (event.button == psyqo::SimplePad::Button::Left) {
            m_h -= 10;
        }
        if (event.button == psyqo::SimplePad::Button::Right) {
            m_h += 10;
        }
        psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(m_trz);
        psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(m_h);
    });
    for (auto& pixel : m_pixels.primitives) {
        pixel.setColor({.r = 0xff, .g = 0x80, .b = 0x33});
    }
    generateTorus();
    psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
    psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(m_trz);
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(m_h);
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());
}

void GTEScene::frame() {
    m_angleX += c_angleXStep;
    m_angleY += c_angleYStep;
    m_angleZ += c_angleZStep;
    if (m_angleX >= 2.0_pi) {
        m_angleX -= 2.0_pi;
    }
    if (m_angleY >= 2.0_pi) {
        m_angleY -= 2.0_pi;
    }
    if (m_angleZ >= 2.0_pi) {
        m_angleZ -= 2.0_pi;
    }

    psyqo::Matrix33 transform =
        psyqo::SoftMath::generateRotationMatrix33(m_angleX, psyqo::SoftMath::Axis::X, &gteDemo.m_trig);
    psyqo::Matrix33 rot =
        psyqo::SoftMath::generateRotationMatrix33(m_angleY, psyqo::SoftMath::Axis::Y, &gteDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::SoftMath::generateRotationMatrix33(&rot, m_angleZ, psyqo::SoftMath::Axis::Z, &gteDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);

    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);

    if (m_projected) {
        for (unsigned i = 0; i < (Torus::Count - 2); i += 3) {
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i + 0]);
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V1>(m_torus.vertices[i + 1]);
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_torus.vertices[i + 2]);
            psyqo::GTE::Kernels::rtpt();
            auto sxy0 = psyqo::GTE::read<psyqo::GTE::Register::SXY0, psyqo::GTE::Safe>();
            int16_t x0 = sxy0 & 0xffff;
            int16_t y0 = sxy0 >> 16;
            auto sxy1 = psyqo::GTE::read<psyqo::GTE::Register::SXY1, psyqo::GTE::Safe>();
            int16_t x1 = sxy1 & 0xffff;
            int16_t y1 = sxy1 >> 16;
            auto sxy2 = psyqo::GTE::read<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>();
            int16_t x2 = sxy2 & 0xffff;
            int16_t y2 = sxy2 >> 16;
            m_pixels.primitives[i + 0].position = {{.x = x0, .y = y0}};
            m_pixels.primitives[i + 1].position = {{.x = x1, .y = y1}};
            m_pixels.primitives[i + 2].position = {{.x = x2, .y = y2}};
        }
        for (unsigned i = Torus::Count - 2; i < Torus::Count; i++) {
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i]);
            psyqo::GTE::Kernels::rtpt();
            auto sxy2 = psyqo::GTE::read<psyqo::GTE::Register::SXY2, psyqo::GTE::Safe>();
            int16_t x = sxy2 & 0xffff;
            int16_t y = sxy2 >> 16;
            m_pixels.primitives[i].position = {{.x = x, .y = y}};
        }
    } else {
        for (unsigned i = 0; i < Torus::Count; i++) {
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i]);
            psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
            auto v = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
            m_pixels.primitives[i].position = {
                {.x = int16_t(v.x.integer<16>() + 160), .y = int16_t(v.y.integer<16>() + 120)}};
        }
    }

    gpu().clear({{.r = 0x68, .g = 0xb0, .b = 0xd8}});
    if (m_projected) {
        gteDemo.m_font.print(gpu(), "Projection: Perspective", {{.x = 4, .y = 4}}, {.r = 0xff, .g = 0xff, .b = 0xff});
        gteDemo.m_font.printf(gpu(), {{.x = 4, .y = 20}}, {.r = 0xff, .g = 0xff, .b = 0xff},
                              "TRZ: %d, H: %d", m_trz, m_h);
    } else {
        gteDemo.m_font.print(gpu(), "Projection: Orthographic", {{.x = 4, .y = 4}}, {.r = 0xff, .g = 0xff, .b = 0xff});
    }
    gpu().sendFragment(m_pixels);
}

int main() { return gteDemo.run(); }
