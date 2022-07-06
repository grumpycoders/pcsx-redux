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

// Our application. The PadTest class will be created statically, and run from `main`.
class PadTest final : public psyqo::Application {
    // We will need both methods to properly set up the application.
    void prepare() override;
    void createScene() override;

  public:
    // We will store the font here. We're not going to use chained DMA to display
    // anything, so we don't need multiple fragments. Only a single one will suffice.
    psyqo::Font<1> m_font;

    // Our pad reader.
    psyqo::SimplePad m_input;
};

// We only have a single since to display the status of the pads.
class PadTestScene final : public psyqo::Scene {
    // Since there's only a single scene, we won't need to override the `start`
    // or `teardown` methods. We will do all the initialization in the application.
    void frame() override;

    // Couple of small helpers.
    void print(int x, int y, bool enabled, const char* text);
    void printPadStatus(psyqo::SimplePad::Pad pad, int column, const char* name);
};

PadTest padTest;
PadTestScene padTestScene;

}  // namespace

// The application's `prepare` method is the location to initialize and activate the GPU.
// We shouldn't do anything else that touches the hardware here however, because interrupts
// aren't initialized yet. We could also create more objects here, but we don't have any.
void PadTest::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

// The `createScene` method will be called automatically to create the first scene. It will
// never exit, so there's no need to cater for the reentrancy case here, but technically,
// this method _can_ be called multiple times, if the last scene got popped out. This would
// be bad in this case because it'd mean we're initializing the pads, and uploading the system
// font multiple times.
void PadTest::createScene() {
    // We don't have a specific font, so let's just use the built-in system one.
    m_font.uploadSystemFont(gpu());
    // During `createScene`, interrupts are enabled, so it's okay to call `SimplePad::initialize`.
    m_input.initialize();
    // And finally we call `pushScene` with the address of our one and only scene. This last
    // call is mandatory for everything to function properly.
    pushScene(&padTestScene);
}

// Using the system font, our display is roughly 40 columns by 15 lines of text. Although the
// font system can draw text at arbitrary positions on the screen, it's a bit easier to consider
// a matrix of characters instead.
void PadTestScene::print(int x, int y, bool enabled, const char* text) {
    y += 2;
    psyqo::Vertex pos = {.x = int16_t(x * 8), .y = int16_t(y * 16)};
    // Doing these lazy initializations is great for readability and encapsulation,
    // but due to the way C++ works, it'll call into the C++ guard functions every
    // time the function gets called, which may be slower than it could if those
    // were in fact globals.
    static const auto WHITE = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    static const auto GRAY = psyqo::Color{{.r = 48, .g = 48, .b = 48}};
    psyqo::Color c = enabled ? WHITE : GRAY;
    padTest.m_font.print(padTest.gpu(), text, pos, c);
}

void PadTestScene::printPadStatus(psyqo::SimplePad::Pad pad, int column, const char* name) {
    auto& input = padTest.m_input;
    print(column + 7, 0, input.isPadConnected(pad), name);
    print(column + 0, 2, input.isButtonPressed(pad, psyqo::SimplePad::Button::Start), "Start");
    print(column + 0, 3, input.isButtonPressed(pad, psyqo::SimplePad::Button::Select), "Select");

    print(column + 0, 5, input.isButtonPressed(pad, psyqo::SimplePad::Button::L1), "L1");
    print(column + 0, 6, input.isButtonPressed(pad, psyqo::SimplePad::Button::R1), "R1");
    print(column + 0, 7, input.isButtonPressed(pad, psyqo::SimplePad::Button::L2), "L2");
    print(column + 0, 8, input.isButtonPressed(pad, psyqo::SimplePad::Button::R2), "R2");
    print(column + 0, 9, input.isButtonPressed(pad, psyqo::SimplePad::Button::L3), "L3");
    print(column + 0, 10, input.isButtonPressed(pad, psyqo::SimplePad::Button::R3), "R3");

    print(column + 10, 2, input.isButtonPressed(pad, psyqo::SimplePad::Button::Up), "Up");
    print(column + 10, 3, input.isButtonPressed(pad, psyqo::SimplePad::Button::Down), "Down");
    print(column + 10, 4, input.isButtonPressed(pad, psyqo::SimplePad::Button::Left), "Left");
    print(column + 10, 5, input.isButtonPressed(pad, psyqo::SimplePad::Button::Right), "Right");

    print(column + 10, 7, input.isButtonPressed(pad, psyqo::SimplePad::Button::Cross), "Cross");
    print(column + 10, 8, input.isButtonPressed(pad, psyqo::SimplePad::Button::Circle), "Circle");
    print(column + 10, 9, input.isButtonPressed(pad, psyqo::SimplePad::Button::Square), "Square");
    print(column + 10, 10, input.isButtonPressed(pad, psyqo::SimplePad::Button::Triangle), "Triangle");
}

// Our rendering function that'll be called periodically.
void PadTestScene::frame() {
    padTest.gpu().clear();
    printPadStatus(psyqo::SimplePad::Pad1, 0, "Pad 1");
    printPadStatus(psyqo::SimplePad::Pad2, 20, "Pad 2");
}

int main() { return padTest.run(); }
