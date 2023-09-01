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
#include "psyqo/bezier.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/lines.hh"
#include "psyqo/scene.hh"
#include "psyqo/trigonometry.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

namespace {

class Bezier final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::Trig<> m_trig;
};

class BezierScene final : public psyqo::Scene {
    void frame() override;
    psyqo::Prim::PolyLine<20> m_lines{{.r = 0xff, .g = 0x80, .b = 0x33}};
    psyqo::Angle m_angle1 = 0.0_pi;
    psyqo::Angle m_angle2 = 0.0_pi;
    constexpr static psyqo::Angle c_angleStep1 = 0.0135_pi;
    constexpr static psyqo::Angle c_angleStep2 = 0.017_pi;
    constexpr static psyqo::Vec2 a = {0.0_fp, 240.0_fp};
    constexpr static psyqo::Vec2 b = {640.0_fp, 240.0_fp};
  public:
    BezierScene() {
        m_lines.points[0] = a;
        m_lines.points[20] = b;
    }
};

// We're instantiating the two objects above right now.
Bezier bezier;
BezierScene bezierScene;

}  // namespace

void Bezier::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W640)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::INTERLACED);
    gpu().initialize(config);
}

void Bezier::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&bezierScene);
}

void BezierScene::frame() {
    m_angle1 += c_angleStep1;
    m_angle2 += c_angleStep2;
    if (m_angle1 > 2.0_pi) {
        m_angle1 -= 2.0_pi;
    }
    if (m_angle2 > 2.0_pi) {
        m_angle2 -= 2.0_pi;
    }
    auto angle1 = psyqo::Angle(bezier.m_trig.sin(m_angle1)) * 0.5_pi;
    auto angle2 = psyqo::Angle(bezier.m_trig.sin(m_angle2)) * 0.5_pi;
    auto p1x = bezier.m_trig.cos(angle1) * 200.0_fp;
    if (p1x < 0) p1x = -p1x;
    auto p1y = bezier.m_trig.sin(angle1) * 200.0_fp + 240.0_fp;
    auto p2x = bezier.m_trig.cos(angle2) * 200.0_fp;
    if (p2x < 0) p2x = -p2x;
    auto p2y = bezier.m_trig.sin(angle2) * 200.0_fp + 240.0_fp;
    psyqo::Vec2 p1({p1x, p1y}), p2({640.0_fp - p2x, p2y});
    // Clear the screen and draw the Bezier lines
    gpu().clear({{.r = 0x68, .g = 0xb0, .b = 0xd8}});
    psyqo::FixedPoint<> t;
    for (int i = 1; i < 20; i++) {
        t += 0.05_fp;
        m_lines.points[i] = psyqo::Bezier::cubic(a, p1, p2, b, t);
    }
    gpu().sendPrimitive(m_lines);

#ifdef DEBUG_BEZIER
    psyqo::Prim::Line line;
    line.pointA = a;
    line.pointB = p1;
    gpu().sendPrimitive(line);
    line.pointA = p2;
    line.pointB = b;
    gpu().sendPrimitive(line);
#endif
}

int main() { return bezier.run(); }
