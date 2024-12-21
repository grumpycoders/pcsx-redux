/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include <stdint.h>

#include "psyqo/advancedpad.hh"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/kernel.hh"
#include "psyqo/scene.hh"
#include "psyqo/xprintf.h"

namespace {

// This example is similar to the padtest example, but it uses the `AdvancedPad` class
// instead of the `SimplePad` class. The `AdvancedPad` class is a bit more complex, but
// it can handle multitaps, which the `SimplePad` class cannot. The `AdvancedPad` class
// is also a bit more efficient, as it doesn't rely on the BIOS to poll the pads.
class MultitapTest final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<1> m_font;
    psyqo::AdvancedPad m_input;
};

class MultitapTestScene final : public psyqo::Scene {
    psyqo::AdvancedPad::Pad m_padIndex = psyqo::AdvancedPad::Pad::Pad1a;
    uintptr_t m_timerId;

    void frame() override;
    void start(Scene::StartReason reason) override;

    // Couple of small helpers.
    void nextPad();
    void print(int x, int y, bool enabled, const char *text);
    void printPadStatus(psyqo::AdvancedPad::Pad pad, int column, const char *name);
    void printPadConnectionStatus(psyqo::AdvancedPad::Pad pad, int row, const char *name);
    void printPadType(psyqo::AdvancedPad::Pad pad, int column, const char *name);
};

MultitapTest multitapTest;
MultitapTestScene multitapTestScene;

}  // namespace

void MultitapTest::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    // Unlike the `SimplePad` class, the `AdvancedPad` class doesn't need to be initialized
    // in the `start` method of the root `Scene` object. It can be initialized here.
    m_input.initialize();
}

void MultitapTest::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&multitapTestScene);
}

// Cycle through the pads to find the next one connected
void MultitapTestScene::nextPad() {
    for (unsigned i = 0; i < 8; i++) {
        if (multitapTest.m_input.isPadConnected(++m_padIndex)) {
            return;  // Found a connected pad
        }
    }

    // No connected pad found, reset index to first pad
    m_padIndex = psyqo::AdvancedPad::Pad::Pad1a;
}

void MultitapTestScene::print(int x, int y, bool enabled, const char *text) {
    y += 2;
    psyqo::Vertex pos = {{.x = int16_t(x * 8), .y = int16_t(y * 16)}};
    static const auto WHITE = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    static const auto GRAY = psyqo::Color{{.r = 48, .g = 48, .b = 48}};
    psyqo::Color c = enabled ? WHITE : GRAY;
    multitapTest.m_font.print(multitapTest.gpu(), text, pos, c);
}

void MultitapTestScene::printPadConnectionStatus(psyqo::AdvancedPad::Pad pad, int row, const char *name) {
    auto &input = multitapTest.m_input;
    print(2, row, input.isPadConnected(pad), name);
}

void MultitapTestScene::printPadStatus(psyqo::AdvancedPad::Pad pad, int column, const char *name) {
    auto &input = multitapTest.m_input;
    print(column + 0, 0, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Start), "Start");
    print(column + 0, 1, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Select), "Select");

    print(column + 0, 3, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L1), "L1");
    print(column + 0, 4, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R1), "R1");
    print(column + 0, 5, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L2), "L2");
    print(column + 0, 6, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R2), "R2");
    print(column + 0, 7, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L3), "L3");
    print(column + 0, 8, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R3), "R3");

    print(column + 10, 0, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Up), "Up");
    print(column + 10, 1, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Down), "Down");
    print(column + 10, 2, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Left), "Left");
    print(column + 10, 3, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Right), "Right");

    print(column + 10, 5, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Cross), "Cross");
    print(column + 10, 6, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Circle), "Circle");
    print(column + 10, 7, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Square), "Square");
    print(column + 10, 8, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Triangle), "Triangle");

    char m_textBuffer[32] = {'\0'};
    const auto padType = input.getPadType(pad);

    // The lower 4-bits of the pad type indicate the number of half-words of pad data
    // The 1st half-word is for the digital switches
    const auto halfWords = padType & 0xf;
    const auto adcBytes = (halfWords - 1) * 2;

    if (halfWords > 1 && padType != psyqo::AdvancedPad::PadType::None) {
        sprintf(m_textBuffer, "ADC[0-%d]", adcBytes - 1);
        print(column + 0, 9, false, m_textBuffer);

        for (int i = 0; i < adcBytes && i < 4; i++) {
            sprintf(m_textBuffer, "%02X ", input.getAdc(pad, i));
            print(column + 10 + (i * 3), 9, true, m_textBuffer);
        }
    }
}

void MultitapTestScene::printPadType(psyqo::AdvancedPad::Pad pad, int column, const char *name) {
    auto &input = multitapTest.m_input;
    char m_textBuffer[16] = {'\0'};
    const auto padType = input.getPadType(pad);

    print(column + 0, 11, true, name);
    switch (padType) {
        case psyqo::AdvancedPad::PadType::Mouse:
            sprintf(m_textBuffer, "Mouse");
            break;
        case psyqo::AdvancedPad::PadType::NegCon:
            sprintf(m_textBuffer, "NegCon");
            break;
        case psyqo::AdvancedPad::PadType::KonamiLightgun:
            sprintf(m_textBuffer, "KonamiLightgun");
            break;
        case psyqo::AdvancedPad::PadType::DigitalPad:
            sprintf(m_textBuffer, "DigitalPad");
            break;
        case psyqo::AdvancedPad::PadType::AnalogStick:
            sprintf(m_textBuffer, "AnalogStick");
            break;
        case psyqo::AdvancedPad::PadType::NamcoLightgun:
            sprintf(m_textBuffer, "NamcoLightgun");
            break;
        case psyqo::AdvancedPad::PadType::AnalogPad:
            sprintf(m_textBuffer, "AnalogPad");
            break;
        case psyqo::AdvancedPad::PadType::Multitap:
            sprintf(m_textBuffer, "Multitap");
            break;
        case psyqo::AdvancedPad::PadType::Jogcon:
            sprintf(m_textBuffer, "Jogcon");
            break;
        case psyqo::AdvancedPad::PadType::ConfigMode:
            sprintf(m_textBuffer, "ConfigMode");
            break;
        case psyqo::AdvancedPad::PadType::None:
            sprintf(m_textBuffer, "None");
            break;
        default:
            sprintf(m_textBuffer, "Unknown");
            break;
    }
    print(column + 10, 11, true, m_textBuffer);
}

void MultitapTestScene::start(Scene::StartReason reason) {
    if (reason == Scene::StartReason::Create) {
        // If we are getting created, create a 5 second periodic timer.
        using namespace psyqo::timer_literals;
        m_timerId = multitapTest.gpu().armPeriodicTimer(5_s, [this](auto) { nextPad(); });
    }
}

void MultitapTestScene::frame() {
    multitapTest.gpu().clear();

    if (multitapTest.m_input.isPadConnected(m_padIndex)) {
        print(1, m_padIndex, true, ">");
    }

    printPadConnectionStatus(psyqo::AdvancedPad::Pad1a, 0, "Pad 1a");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad1b, 1, "Pad 1b");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad1c, 2, "Pad 1c");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad1d, 3, "Pad 1d");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad2a, 4, "Pad 2a");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad2b, 5, "Pad 2b");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad2c, 6, "Pad 2c");
    printPadConnectionStatus(psyqo::AdvancedPad::Pad2d, 7, "Pad 2d");

    printPadStatus(static_cast<psyqo::AdvancedPad::Pad>(m_padIndex), 16, "Pad Status");
    printPadType(static_cast<psyqo::AdvancedPad::Pad>(m_padIndex), 16, "Pad Type");
}

int main() { return multitapTest.run(); }
