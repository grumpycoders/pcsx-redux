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

#include <EASTL/string.h>

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

// This example is the same as the base hello world, except that
// it's going to allocate memory instead of using static objects.
namespace {

class Hello final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    Hello() : m_text("Hello World!") {}
    psyqo::Font<> m_font;
    eastl::string m_text;
};

class HelloScene final : public psyqo::Scene {
    void frame() override;

    uint8_t m_anim = 0;
    bool m_direction = true;
};

Hello* hello = nullptr;

}  // namespace

void Hello::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Hello::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(new HelloScene);
}

void HelloScene::frame() {
    if (m_anim == 0) {
        m_direction = true;
    } else if (m_anim == 255) {
        m_direction = false;
    }
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    bg.r = m_anim;
    gpu().clear(bg);
    if (m_direction) {
        m_anim++;
    } else {
        m_anim--;
    }

    psyqo::Color c = {{.r = 255, .g = 255, .b = uint8_t(255 - m_anim)}};
    hello->m_font.print(gpu(), hello->m_text, {{.x = 16, .y = 32}}, c);
}

int main() {
    hello = new Hello();
    return hello->run();
}
