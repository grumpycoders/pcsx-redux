/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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
    psyqo::Font<> m_font;
    psyqo::AdvancedPad m_input;
};

class MultitapTestScene final : public psyqo::Scene {
    psyqo::AdvancedPad::Pad m_padIndex = psyqo::AdvancedPad::Pad::Pad1a;
    uintptr_t m_timerId;

    void frame() override;
    void start(Scene::StartReason reason) override;

    // Couple of small helpers.
    void nextPad();
    void print(int x, int y, bool enabled, const char *format, ...);
    void printPadList(int column);
    void printPadStatus(psyqo::AdvancedPad::Pad pad, int column);
    void printPadType(psyqo::AdvancedPad::Pad pad, int column, const char *name);

    const char *c_padNames[8] = {"1a", "1b", "1c", "1d", "2a", "2b", "2c", "2d"};
    const psyqo::Color c_colorWhite = {{.r = 255, .g = 255, .b = 255}};
    const psyqo::Color c_colorGray = {{.r = 48, .g = 48, .b = 48}};
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
    // PollingMode::Fast is used to reduce input lag, but it will increase CPU usage.
    // PollingMode::Normal is the default, and will poll one port per frame.
    m_input.initialize(psyqo::AdvancedPad::PollingMode::Fast);
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

void MultitapTestScene::print(int x, int y, bool enabled, const char *format, ...) {
    va_list args;
    const psyqo::Vertex pos = {{.x = int16_t(x * 8), .y = int16_t(y * 16)}};
    const psyqo::Color c = enabled ? c_colorWhite : c_colorGray;

    va_start(args, format);
    multitapTest.m_font.vprintf(multitapTest.gpu(), pos, c, format, args);
    va_end(args);
}

void MultitapTestScene::printPadList(int column) {
    // Print pad names and selected pad indicator
    for (int i = 0; i < 8; i++) {
        const auto pad = static_cast<psyqo::AdvancedPad::Pad>(i);
        const bool isConnected = multitapTest.m_input.isPadConnected(pad);
        const char padIndicator = (m_padIndex == pad && isConnected) ? '>' : ' ';
        print(column, i + 2, isConnected, "%cPad %s", padIndicator, c_padNames[i]);
    }
}

void MultitapTestScene::printPadStatus(psyqo::AdvancedPad::Pad pad, int column) {
    const auto &input = multitapTest.m_input;
    print(column + 0, 2, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Start), "Start");
    print(column + 0, 3, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Select), "Select");

    print(column + 0, 5, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L1), "L1");
    print(column + 0, 6, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R1), "R1");
    print(column + 0, 7, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L2), "L2");
    print(column + 0, 8, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R2), "R2");
    print(column + 0, 9, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::L3), "L3");
    print(column + 0, 10, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::R3), "R3");

    print(column + 10, 2, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Up), "Up");
    print(column + 10, 3, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Down), "Down");
    print(column + 10, 4, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Left), "Left");
    print(column + 10, 5, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Right), "Right");

    print(column + 10, 7, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Cross), "Cross");
    print(column + 10, 8, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Circle), "Circle");
    print(column + 10, 9, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Square), "Square");
    print(column + 10, 10, input.isButtonPressed(pad, psyqo::AdvancedPad::Button::Triangle), "Triangle");

    const auto padType = input.getPadType(pad);

    // The lower 4-bits of the pad type indicate the number of half-words of pad data
    // The 1st half-word is for the digital switches
    const auto halfWords = padType & 0xf;
    const auto adcBytes = (halfWords - 1) * 2;

    if (halfWords > 1 && padType != psyqo::AdvancedPad::PadType::None) {
        print(column + 0, 11, false, "ADC[0-%d]", adcBytes - 1);

        for (int i = 0; i < adcBytes; i++) {
            print(column + 10 + (i * 2), 11, true, "%02X", input.getAdc(pad, i));
        }
    }
}

void MultitapTestScene::printPadType(psyqo::AdvancedPad::Pad pad, int column, const char *name) {
    const auto padType = multitapTest.m_input.getPadType(pad);
    const char *padTypeStr;

    switch (padType) {
        case psyqo::AdvancedPad::PadType::Mouse:
            padTypeStr = "Mouse";
            break;
        case psyqo::AdvancedPad::PadType::NegCon:
            padTypeStr = "NegCon";
            break;
        case psyqo::AdvancedPad::PadType::KonamiLightgun:
            padTypeStr = "KonamiLightgun";
            break;
        case psyqo::AdvancedPad::PadType::DigitalPad:
            padTypeStr = "DigitalPad";
            break;
        case psyqo::AdvancedPad::PadType::AnalogStick:
            padTypeStr = "AnalogStick";
            break;
        case psyqo::AdvancedPad::PadType::NamcoLightGun:
            padTypeStr = "NamcoLightGun";
            break;
        case psyqo::AdvancedPad::PadType::AnalogPad:
            padTypeStr = "AnalogPad";
            break;
        case psyqo::AdvancedPad::PadType::Multitap:
            padTypeStr = "Multitap";
            break;
        case psyqo::AdvancedPad::PadType::JogCon:
            padTypeStr = "JogCon";
            break;
        case psyqo::AdvancedPad::PadType::FishingCon:
            padTypeStr = "FishingCon";
            break;
        case psyqo::AdvancedPad::PadType::ConfigMode:
            padTypeStr = "ConfigMode";
            break;
        case psyqo::AdvancedPad::PadType::None:
            padTypeStr = "None";
            break;
        default:
            padTypeStr = "Unknown";
            break;
    }
    print(column + 0, 13, true, name);
    print(column + 10, 13, true, "%s %02x", padTypeStr, padType);
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

    printPadList(1);
    printPadStatus(static_cast<psyqo::AdvancedPad::Pad>(m_padIndex), 10);
    printPadType(static_cast<psyqo::AdvancedPad::Pad>(m_padIndex), 10, "Type");
}

int main() { return multitapTest.run(); }
