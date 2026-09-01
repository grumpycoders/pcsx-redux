/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include "psyqo/primitives/lines.hh"

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

namespace {

// A PSYQo software needs to declare one `Application` object.
class Lines final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
};

// And we need at least one scene to be created.
class LinesScene final : public psyqo::Scene {
    void frame() override;

    // We'll have some simple animation going on, so we
    // need to keep track of our state here.
    uint8_t m_anim = 0;
    bool m_direction = true;
};

// We're instantiating the two objects above right now.
Lines lines;
LinesScene linesScene;

}  // namespace

void Lines::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Lines::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&linesScene);
}

void LinesScene::frame() {
    if (m_anim == 0) {
        m_direction = true;
    } else if (m_anim == 255) {
        m_direction = false;
    }
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    bg.r = m_anim;
    lines.gpu().clear(bg);
    if (m_direction) {
        m_anim++;
    } else {
        m_anim--;
    }

    // This isn't the most efficient method, but it works.
    psyqo::Prim::Line line1(psyqo::Color{{.r = 128, .g = 128, .b = 128}});
    line1.pointA.x = 50;
    line1.pointB.x = 300;
    line1.pointA.y = 50;
    line1.pointB.y = m_anim;
    lines.gpu().sendPrimitive(line1);

    psyqo::Prim::Line line2(psyqo::Color{{.r = 15, .g = 230, .b = 42}});
    line2.pointA.x = 50;
    line2.pointB.x = 300;
    line2.pointA.y = 200;
    line2.pointB.y = 255 - m_anim;
    lines.gpu().sendPrimitive(line2);

    psyqo::Color c = {{.r = 255, .g = 255, .b = uint8_t(255 - m_anim)}};
    lines.m_font.print(lines.gpu(), "Lines!", {{.x = 16, .y = 32}}, c);
}

int main() { return lines.run(); }
