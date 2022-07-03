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
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"

namespace {

class PadTest final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::SimplePad m_input;
};

class PadTestScene final : public psyqo::Scene {
    void frame() override;
    void printf(int x, int y, bool enabled, const char* format, ...);
    void printPadStatus(psyqo::SimplePad::Pad pad, int column, const char* name);

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

void PadTestScene::printf(int x, int y, bool enabled, const char* format, ...) {
    va_list args;
    va_start(args, format);
    psyqo::Vertex pos = {.x = int16_t(x * 8), .y = int16_t(y * 16)};
    psyqo::Color c =
        enabled ? psyqo::Color{.r = 0xff, .g = 0xff, .b = 0xff} : psyqo::Color{.r = 0x30, .g = 0x30, .b = 0x30};
    padTest.m_font.vprintf(padTest.gpu(), pos, c, format, args);
    va_end(args);
}

void PadTestScene::printPadStatus(psyqo::SimplePad::Pad pad, int column, const char* name) {
    auto& input = padTest.m_input;
    printf(column + 7, 0, input.isPadConnected(pad), name);
    printf(column + 0, 2, input.isButtonPressed(pad, psyqo::SimplePad::Button::Start), "Start");
    printf(column + 0, 3, input.isButtonPressed(pad, psyqo::SimplePad::Button::Select), "Select");

    printf(column + 0, 5, input.isButtonPressed(pad, psyqo::SimplePad::Button::L1), "L1");
    printf(column + 0, 6, input.isButtonPressed(pad, psyqo::SimplePad::Button::R1), "R1");
    printf(column + 0, 7, input.isButtonPressed(pad, psyqo::SimplePad::Button::L2), "L2");
    printf(column + 0, 8, input.isButtonPressed(pad, psyqo::SimplePad::Button::R2), "R2");
    printf(column + 0, 9, input.isButtonPressed(pad, psyqo::SimplePad::Button::L3), "L3");
    printf(column + 0, 10, input.isButtonPressed(pad, psyqo::SimplePad::Button::R3), "R3");

    printf(column + 10, 2, input.isButtonPressed(pad, psyqo::SimplePad::Button::Up), "Up");
    printf(column + 10, 3, input.isButtonPressed(pad, psyqo::SimplePad::Button::Down), "Down");
    printf(column + 10, 4, input.isButtonPressed(pad, psyqo::SimplePad::Button::Left), "Left");
    printf(column + 10, 5, input.isButtonPressed(pad, psyqo::SimplePad::Button::Right), "Right");

    printf(column + 10, 7, input.isButtonPressed(pad, psyqo::SimplePad::Button::Cross), "Cross");
    printf(column + 10, 8, input.isButtonPressed(pad, psyqo::SimplePad::Button::Circle), "Circle");
    printf(column + 10, 9, input.isButtonPressed(pad, psyqo::SimplePad::Button::Square), "Square");
    printf(column + 10, 10, input.isButtonPressed(pad, psyqo::SimplePad::Button::Triangle), "Triangle");
}

void PadTestScene::frame() {
    auto& gpu = padTest.gpu();
    gpu.clear();
    printPadStatus(psyqo::SimplePad::Pad1, 0, "Pad 1");
    printPadStatus(psyqo::SimplePad::Pad2, 20, "Pad 2");
}

int main() { return padTest.run(); }
