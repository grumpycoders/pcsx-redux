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

// As usual, we need to create a class that inherits from psyqo::Application.
class GTEDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    // We'll display some text on the screen, so we need a font.
    psyqo::Font<> m_font;
    // We need a trigonometry object to perform the calculations.
    psyqo::Trig<> m_trig;
    // We'll use a SimplePad to control the demo.
    psyqo::SimplePad m_pad;
};

GTEDemo gteDemo;

// Our Torus will be a template class, so that we can easily change the number of circles and points.
template <size_t Circles, size_t Points>
struct TorusTemplate {
    static constexpr size_t Count = Circles * Points;
    eastl::array<psyqo::GTE::PackedVec3, Circles * Points> vertices;
    void generate() {
        constexpr psyqo::Angle incrementOutside = 2.0_pi / Circles;
        constexpr psyqo::Angle incrementInside = 2.0_pi / Points;

        unsigned index = 0;
        // We're going to generate circles, rotating them around the Z axis.
        for (psyqo::Angle outside = 0.0_pi; outside < 2.0_pi; outside += incrementOutside) {
            // Generate a rotation matrix for the current angle.
            auto rot = psyqo::SoftMath::generateRotationMatrix33(outside, psyqo::SoftMath::Axis::Z, &gteDemo.m_trig);
            // Uploading the matrix to the GTE. The matrix won't be used until we call mvmva, so we can use the unsafe
            // GTE write version.
            psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(rot);
            // Generate the points for the current circle.
            for (psyqo::Angle inside = 0; inside < 2.0_pi; inside += incrementInside) {
                psyqo::Vec3 v;
                auto c = gteDemo.m_trig.cos(inside);
                auto s = gteDemo.m_trig.sin(inside);
                // The circles are offset by 4.0 units along the Y axis, for a proper torus shape. They have a radius of
                // 1.0 units.
                v.x = 0.0_fp;
                v.y = c + 4.0_fp;
                v.z = s;
                // We're multiplying the vector by the rotation matrix we uploaded earlier. We're uploading the vector
                // to GTE's vector 0, and we are going to immediately use mvmva to multiply it by the rotation matrix,
                // so we need to use the safe GTE write version.
                psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(v);
                // Call the mvmva kernel. This will multiply the vector by the rotation matrix, and store the result in
                // the SV pseudo-register.
                psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
                // Read the result from the SV pseudo-register. We're using the unsafe GTE read version, because we
                // know the codegen here will be fine. Also, the assembler should be able to know how to insert
                // hazard stalls if needed.
                vertices[index++] = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
            }
        }
    }
};

class GTEScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;
    // Our torus will rotate around the X, Y and Z axes, so we need to keep track of the angles.
    psyqo::Angle m_angleX = 0.0_pi;
    psyqo::Angle m_angleY = 0.0_pi;
    psyqo::Angle m_angleZ = 0.0_pi;
    // We'll rotate the torus by a small amount every frame.
    constexpr static psyqo::Angle c_angleXStep = 0.001_pi;
    constexpr static psyqo::Angle c_angleYStep = 0.002_pi;
    constexpr static psyqo::Angle c_angleZStep = 0.003_pi;
    // We instantiate a TorusTemplate with 32 circles and 16 points per circle.
    typedef TorusTemplate<32, 16> Torus;
    Torus m_torus;
    // We'll use the GTE to project the torus onto the screen. The Z translation and the H value control the
    // projection. These values are stored in the GTE registers TRZ and H, respectively. These initial values
    // give out a nice perspective projection. The d-pad will be used to change these values.
    int32_t m_trz = 60000;
    uint16_t m_h = 300;
    // We'll just use a bunch of pixels to draw the torus, one pixel per vertex.
    psyqo::Fragments::FixedFragment<psyqo::Prim::Pixel, Torus::Count> m_pixels;
    // We'll use the cross button to switch between perspective and orthographic projection, so we need to keep
    // track of the current projection mode.
    bool m_projected = true;
};

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

void GTEScene::start(StartReason reason) {
    // We use the joypad to control the demo, so we need to set up the joypad event handler.
    gteDemo.m_pad.setOnEvent([this](auto event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        // We'll use the cross button to switch between perspective and orthographic projection.
        if (event.button == psyqo::SimplePad::Button::Cross) {
            m_projected = !m_projected;
        }
        // We'll use the d-pad to change the Z translation and the H value.
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
        // Upload the new TRZ and H values to the GTE. The GTE will use these values the next time we call rtpt.
        // We're using the unsafe GTE write version because the rtpt kernel will be called way later, so we don't
        // need to worry about hazards.
        psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(m_trz);
        psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(m_h);
    });
    // Initialize our primitives.
    for (auto& pixel : m_pixels.primitives) {
        pixel.setColor({.r = 0xff, .g = 0x80, .b = 0x33});
    }
    // Generate the torus.
    m_torus.generate();
    // Set our GTE initial values. We're using the unsafe GTE write version because we're
    // very far away from the rtpt kernel, so we don't need to worry about hazards.
    // TRX and TRY are set to 0, as we're not going to do any translation on the X and Y axes.
    psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
    psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(m_trz);
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(m_h);
    // We're going to project the torus onto the screen, so we need to set up the projection
    // parameters to offset the projection center to the center of the screen. We have a 320x240
    // screen, so the center is at (160, 120).
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());
}

void GTEScene::frame() {
    // Bump the angles, and wrap them around if needed.
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

    // Generate the rotation matrix for the current angles, by multiplying the three rotation matrices. This
    // is done in software, because the GTE doesn't have any way to multiply matrices. This is technically
    // costly, but it is done only once per frame, so it's not a big deal.
    auto transform = psyqo::SoftMath::generateRotationMatrix33(m_angleX, psyqo::SoftMath::Axis::X, &gteDemo.m_trig);
    auto rot = psyqo::SoftMath::generateRotationMatrix33(m_angleY, psyqo::SoftMath::Axis::Y, &gteDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);
    psyqo::SoftMath::generateRotationMatrix33(&rot, m_angleZ, psyqo::SoftMath::Axis::Z, &gteDemo.m_trig);
    psyqo::SoftMath::multiplyMatrix33(&transform, &rot, &transform);

    // Upload the rotation matrix to the GTE. We're using the unsafe GTE write version because we're
    // still away from the rtpt kernel.
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);

    if (!m_projected) {
        // In orthographic projection, we can just multiply the vertices by the rotation matrix, and
        // use the result directly. The mvmva kernel works on only one vertex at a time, so we don't
        // need any special trickery here.
        for (unsigned i = 0; i < Torus::Count; i++) {
            // Load the vertex into the GTE vector 0.
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i]);
            // Multiply the vertex by the rotation matrix, and store the result in the SV pseudo-register.
            psyqo::GTE::Kernels::mvmva<psyqo::GTE::Kernels::MX::RT, psyqo::GTE::Kernels::MV::V0>();
            auto v = psyqo::GTE::readUnsafe<psyqo::GTE::PseudoRegister::SV>();
            // We'll need to scale the resulting vertex a bit, because the GTE functions using 3.12 fixed-point
            // values, which means we're constrained to get values between -8.0 and 8.0. We'll scale the
            // vertex by 16. We'll also offset the vertex by 160 and 120, to center it on the screen.
            m_pixels.primitives[i].position = {
                {.x = int16_t(v.x.integer<16>() + 160), .y = int16_t(v.y.integer<16>() + 120)}};
        }
    } else {
        // When doing perspective projection, we want to use the rtpt kernel, which will project three
        // vertices at a time. We could trick our input vertices buffer to be a multiple of three, but
        // we want to demonstrate using both rtpt and rtps, so we'll just use the rtps kernel for the
        // last few vertices. We do not make assumptions on the number of vertices, in order to keep
        // our torus template generic.
        unsigned i = 0;
        for (; i < (Torus::Count - 2); i += 3) {
            // Load the three vertices into the GTE vector 0, 1, and 2. Only v2 needs to be loaded using
            // the safe GTE write version, because we're calling rtpt immediately after.
            psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i + 0]);
            psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(m_torus.vertices[i + 1]);
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V2>(m_torus.vertices[i + 2]);
            // Call the rtpt kernel. This will project the three vertices, and store the result in the
            // SXY0, SXY1, and SXY2 registers.
            psyqo::GTE::Kernels::rtpt();
            // Then, read the projected vertices from the SXY0, SXY1 and SXY2 registers, into the
            // primitives buffer. No adjustment is needed, because the kernel will have properly scaled
            // and offset the vertices.
            psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&m_pixels.primitives[i + 0].position.packed);
            psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&m_pixels.primitives[i + 1].position.packed);
            psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&m_pixels.primitives[i + 2].position.packed);
        }
        // For the last vertices, we'll use the rtps kernel. This kernel will project a single
        // vertex, and store the result in the SXY2 register. Same as before, we can just read
        // the result from the SXY2 register, and store it in the primitives buffer directly.
        for (; i < Torus::Count; i++) {
            psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(m_torus.vertices[i]);
            psyqo::GTE::Kernels::rtps();
            psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&m_pixels.primitives[i].position.packed);
        }
    }

    // Finally, draw the frame.
    gpu().clear({{.r = 0x34, .g = 0x58, .b = 0x6c}});
    if (m_projected) {
        gteDemo.m_font.print(gpu(), "Projection: Perspective", {{.x = 4, .y = 4}}, {.r = 0xff, .g = 0xff, .b = 0xff});
        gteDemo.m_font.printf(gpu(), {{.x = 4, .y = 20}}, {.r = 0xff, .g = 0xff, .b = 0xff}, "TRZ: %d, H: %d", m_trz,
                              m_h);
    } else {
        gteDemo.m_font.print(gpu(), "Projection: Orthographic", {{.x = 4, .y = 4}}, {.r = 0xff, .g = 0xff, .b = 0xff});
    }
    gpu().sendFragment(m_pixels);
}

int main() { return gteDemo.run(); }
