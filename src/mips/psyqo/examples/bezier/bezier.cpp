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
    // This will hold the lines that make up the Bezier curve.
    psyqo::Prim::PolyLine<20> m_lines{{.r = 0xff, .g = 0xff, .b = 0xff}};
    // The two angles representing the control points.
    psyqo::Angle m_angle1 = 0.0_pi;
    psyqo::Angle m_angle2 = 0.0_pi;
    // The step size for the angles.
    constexpr static psyqo::Angle c_angleStep1 = 0.0135_pi;
    constexpr static psyqo::Angle c_angleStep2 = 0.017_pi;
    // The beginning and end points of the Bezier curve.
    constexpr static psyqo::Vec2 a = {0.0_fp, 240.0_fp};
    constexpr static psyqo::Vec2 b = {640.0_fp, 240.0_fp};
  public:
    BezierScene() {
        // Set the first and last points of the Bezier curve in the PolyLine,
        // since they will never change.
        m_lines.points[0] = a;
        m_lines.points[20] = b;
    }
};

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
    // Update the angles of the control points.
    m_angle1 += c_angleStep1;
    m_angle2 += c_angleStep2;

    // Wrap the angles around if they go over 2pi.
    if (m_angle1 > 2.0_pi) {
        m_angle1 -= 2.0_pi;
    }
    if (m_angle2 > 2.0_pi) {
        m_angle2 -= 2.0_pi;
    }

    // The angles above are used to calculate another set of angles, in order to
    // create a smoother animation. This means the speed of the angles will
    // follow a sine wave. Angles are divided by 2 because the sine wave goes
    // from -1 to 1, and the angles need to go from -pi/2 to pi/2. Remember that
    // the Angle class is a fixed point type, with the "1.0" value being equal
    // to the value "pi", meaning that the value "pi/2" is equal to "0.5".
    auto angle1 = psyqo::Angle(bezier.m_trig.sin(m_angle1)) / 2;
    auto angle2 = psyqo::Angle(bezier.m_trig.sin(m_angle2)) / 2;

    // Calculate the control points based on the angles.
    auto p1x = bezier.m_trig.cos(angle1) * 200.0_fp;
    auto p1y = bezier.m_trig.sin(angle1) * 200.0_fp + 240.0_fp;
    auto p2x = bezier.m_trig.cos(angle2) * 200.0_fp;
    auto p2y = bezier.m_trig.sin(angle2) * 200.0_fp + 240.0_fp;

    if (p1x < 0) p1x = -p1x;
    if (p2x < 0) p2x = -p2x;

    psyqo::Vec2 p1({p1x, p1y}), p2({640.0_fp - p2x, p2y});

    // Clear the screen.
    gpu().clear({{.r = 0, .g = 0, .b = 0}});

    // Calculate the points of the Bezier curve and store them in the PolyLine.
    psyqo::FixedPoint<> t;
    for (int i = 1; i < 20; i++) {
        t += 0.05_fp;
        m_lines.points[i] = psyqo::Bezier::cubic(a, p1, p2, b, t);
    }

    // Draw the PolyLine.
    gpu().sendPrimitive(m_lines);

#ifdef DEBUG_BEZIER
    // Draw the control points.
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
