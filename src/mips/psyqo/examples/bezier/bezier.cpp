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
#include "psyqo/primitives/quads.hh"
#include "psyqo/scene.hh"
#include "psyqo/trigonometry.hh"

using namespace psyqo::trig_literals;

namespace {

class Bezier final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
};

class BezierScene final : public psyqo::Scene {
    void frame() override;
    psyqo::Prim::Line m_line{{.r = 0xff, .g = 0x80, .b = 0x33}};
    int m_p1 = 0;
    int m_p2 = 0;
    int m_direction1 = 2;
    int m_direction2 = 3;
};

// We're instantiating the two objects above right now.
Bezier bezier;
BezierScene bezierScene;

}  // namespace

void Bezier::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Bezier::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&bezierScene);
}

void BezierScene::frame() {
    using namespace psyqo::fixed_point_literals;
    const psyqo::Vec2 a = {0.0_fp, 100.0_fp};
    const psyqo::Vec2 b = {320.0_fp, 100.0_fp};
    psyqo::Vec2 m = a;
    m_p1 += m_direction1;
    m_p2 += m_direction2;
    if (m_p1 < 0) {
        m_direction1 = 2;
    } else if (m_p1 > 240) {
        m_direction1 = -2;
    }
    if (m_p2 < 0) {
        m_direction2 = 3;
    } else if (m_p2 > 240) {
        m_direction2 = -3;
    }
    psyqo::FixedPoint<> p1(m_p1, 0);
    psyqo::FixedPoint<> p2(m_p2, 0);
    // Clear the screen and draw the Bezier lines
    gpu().clear({{.r = 0x68, .g = 0xb0, .b = 0xd8}});
    psyqo::FixedPoint<> t = 0.05_fp;
    for (int i = 1; i < 20; ++i) {
        t += 0.05_fp;
        const psyqo::Vec2 n = psyqo::Bezier::cubic(a, {0.0_fp, p1}, {320.0_fp, p2}, b, t);
        m_line.pointA.x = m.x.integer();
        m_line.pointA.y = m.y.integer();
        m_line.pointB.x = n.x.integer();
        m_line.pointB.y = n.y.integer();
        gpu().sendPrimitive(m_line);
        m = n;
    }
    gpu().sendPrimitive(m_line);
}

int main() { return bezier.run(); }
