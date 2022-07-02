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

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/input.hh"
#include "psyqo/scene.hh"

namespace {

class PadTest final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::Input m_input;
};

class PadTestScene final : public psyqo::Scene {
    void frame() override;

    uint8_t m_anim = 0;
    bool m_direction = true;
};

PadTest padTest;
PadTestScene padTestScene;

}  // namespace

void PadTest::prepare() {
    auto config = psyqo::GPU::Configuration();
    config.setResolution(psyqo::GPU::Resolution::W320)
        .setVideoMode(psyqo::GPU::VideoMode::AUTO)
        .setColorMode(psyqo::GPU::ColorMode::C15BITS)
        .setInterlace(false);
    gpu().initialize(config);
}

void PadTest::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&padTestScene);
}

void PadTestScene::frame() {
    auto& gpu = padTest.gpu();
    auto& font = padTest.m_font;
    gpu.clear();
    font.printf(gpu, {.x = 16, .y = 32}, {.r = 255, .g = 255, .b = 255}, "Start pressed: %s",
                padTest.m_input.isButtonPressed(psyqo::Input::Pad1, psyqo::Input::Start) ? "true" : "false");
}

int main() { return padTest.run(); }
