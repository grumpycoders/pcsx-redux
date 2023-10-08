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

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/scene.hh"
#include "psyqo/trigonometry.hh"

using namespace psyqo::trig_literals;

namespace {

class Math final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    // We need a trigonometry object to perform the calculations.
    // We're using the default template parameters, which means
    // that the object will use psyqo::FixedPoint<12, int32_t> as its
    // internal representation. This is a 20.12 fixed-point number,
    // which will be the results of the calculations.
    psyqo::Trig<> m_trig;
};

class MathScene final : public psyqo::Scene {
    void frame() override;
    // This will hold the current angle of the quad. Its constructor
    // initializes it to 0.
    psyqo::Angle m_angle;
    // This is our step size. We'll add it to m_angle every frame.
    // Its value is 0.01*Pi radians, or 1.8 degrees. The float literal
    // is converted to a psyqo::Angle object by the compiler.
    constexpr static psyqo::Angle c_angleStep = 0.01_pi;
    // This is the quad we'll draw.
    psyqo::Prim::Quad m_quad{{.r = 0xff, .g = 0x80, .b = 0x33}};
};

// We're instantiating the two objects above right now.
Math math;
MathScene mathScene;

}  // namespace

void Math::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Math::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&mathScene);
}

void MathScene::frame() {
    // We'll rotate the quad by a small amount every frame.
    m_angle += c_angleStep;
    // If the angle is greater than 2*Pi, we'll subtract 2*Pi from it.
    // This is to prevent the angle from growing too large and overflowing,
    // as it is still an integer internally.
    if (m_angle >= 2.0_pi) {
        m_angle -= 2.0_pi;
    }

    // This is the vertex we'll rotate.
    constexpr auto c_vertex = psyqo::Vertex{{.x = 100, .y = 0}};

    // Perform a rotation of c_vertex by m_angle. This is the standard
    // rotation matrix multiplication.
    auto cos = math.m_trig.cos(m_angle);
    auto sin = math.m_trig.sin(m_angle);
    auto x = (c_vertex.x * cos - c_vertex.y * sin).integer();
    auto y = (c_vertex.x * sin + c_vertex.y * cos).integer();

    // Then draw a quad with the rotated vertex.
    m_quad.pointA = {{.x = static_cast<int16_t>(x + 160), .y = static_cast<int16_t>(y + 120)}};
    m_quad.pointB = {{.x = static_cast<int16_t>(-y + 160), .y = static_cast<int16_t>(x + 120)}};
    m_quad.pointC = {{.x = static_cast<int16_t>(y + 160), .y = static_cast<int16_t>(-x + 120)}};
    m_quad.pointD = {{.x = static_cast<int16_t>(-x + 160), .y = static_cast<int16_t>(-y + 120)}};

    // Clear the screen and draw the quad.
    gpu().clear({{.r = 0x68, .g = 0xb0, .b = 0xd8}});
    gpu().sendPrimitive(m_quad);
}

int main() { return math.run(); }
