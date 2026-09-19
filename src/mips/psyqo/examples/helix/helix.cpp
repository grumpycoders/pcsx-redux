/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

// A text entry built on psyqo::HelixSelector. Note what lives where: the selector
// owns the spiral and the selection, and this file owns every single thing about
// what the items MEAN. Casing is drawn here, not selected there; the text buffer
// is a char array down at the bottom of this file; and "submit" is just an entry
// in the atlas that this file happens to treat as terminal.

#include <stdint.h>

#include "psyqo/advancedpad.hh"
#include "psyqo/application.hh"
#include "psyqo/atan2.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/helix-selector.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/primitives/triangles.hh"
#include "psyqo/scene.hh"
#include "psyqo/trigonometry.hh"

namespace {

using namespace psyqo::timer_literals;

// Hold a direction and it keeps going after a moment, like any text entry.
constexpr uint32_t c_repeatDelay = 350_ms;  // before auto-repeat kicks in
constexpr uint32_t c_repeatRate = 60_ms;    // one item per tick after that

// The item list. Index is the only thing the selector ever knows about these.
enum Kind : uint8_t { Letter, Digit, Symbol, Action };
struct Item {
    char lower;
    char upper;
    Kind kind;
};

constexpr Item c_items[] = {
    {'a', 'A', Letter}, {'b', 'B', Letter}, {'c', 'C', Letter}, {'d', 'D', Letter}, {'e', 'E', Letter},
    {'f', 'F', Letter}, {'g', 'G', Letter}, {'h', 'H', Letter}, {'i', 'I', Letter}, {'j', 'J', Letter},
    {'k', 'K', Letter}, {'l', 'L', Letter}, {'m', 'M', Letter}, {'n', 'N', Letter}, {'o', 'O', Letter},
    {'p', 'P', Letter}, {'q', 'Q', Letter}, {'r', 'R', Letter}, {'s', 'S', Letter}, {'t', 'T', Letter},
    {'u', 'U', Letter}, {'v', 'V', Letter}, {'w', 'W', Letter}, {'x', 'X', Letter}, {'y', 'Y', Letter},
    {'z', 'Z', Letter}, {'0', '0', Digit},  {'1', '1', Digit},  {'2', '2', Digit},  {'3', '3', Digit},
    {'4', '4', Digit},  {'5', '5', Digit},  {'6', '6', Digit},  {'7', '7', Digit},  {'8', '8', Digit},
    {'9', '9', Digit},  {'.', '.', Symbol}, {',', ',', Symbol}, {'-', '_', Symbol}, {' ', ' ', Symbol},
    {'<', '<', Action},  // erase
    {'>', '>', Action},  // submit
};
constexpr unsigned c_itemCount = sizeof(c_items) / sizeof(c_items[0]);
constexpr unsigned c_eraseIndex = c_itemCount - 2;
constexpr unsigned c_submitIndex = c_itemCount - 1;

class Helix final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<48> m_font;
    psyqo::AdvancedPad m_input;
    psyqo::Trig<> m_trig;
};

class HelixScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;

    psyqo::HelixSelector m_selector;
    char m_text[17] = {};
    unsigned m_textLen = 0;
    bool m_upper = false;
    bool m_prevCross = false;
    bool m_prevLeft = false;
    bool m_prevRight = false;
    bool m_submitted = false;
    uint32_t m_activations = 0;

    int32_t m_held = 0;  // -1, 0 or +1: which way the d-pad is being held
    uint32_t m_heldSince = 0;

    void onEvent(psyqo::HelixSelector::Event e);
    void readInput();
};

Helix helix;
HelixScene helixScene;

psyqo::Color colorFor(const Item& item, psyqo::FixedPoint<> fade, bool selected) {
    uint8_t r, g, b;
    switch (item.kind) {
        case Letter:
            r = 24;
            g = 148;
            b = 112;
            break;
        case Digit:
            r = 32;
            g = 110;
            b = 150;
            break;
        case Symbol:
            r = 108;
            g = 68;
            b = 172;
            break;
        default:
            r = 208;
            g = 116;
            b = 24;
            break;
    }
    if (selected) {
        r = uint8_t(r + (255 - r) / 2);
        g = uint8_t(g + (255 - g) / 2);
        b = uint8_t(b + (255 - b) / 2);
    }
    int32_t f = fade.raw();
    if (f < 0) f = 0;
    if (f > int32_t(psyqo::FixedPoint<>::scale)) f = psyqo::FixedPoint<>::scale;
    r = uint8_t((int32_t(r) * f) >> 12);
    g = uint8_t((int32_t(g) * f) >> 12);
    b = uint8_t((int32_t(b) * f) >> 12);
    return psyqo::Color{{.r = r, .g = g, .b = b}};
}

}  // namespace

void Helix::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Helix::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&helixScene);
}

void HelixScene::start(StartReason reason) {
    psyqo::HelixSelector::Config config;
    config.center = {{.x = 160, .y = 120}};
    // 42 items over 14 spokes is exactly three turns, so the list wrap lands on a
    // lap boundary and the join between turns does not slip round.
    config.itemsPerTurn = 14;
    m_selector.setup(c_itemCount, config);
    m_selector.setOnEvent([this](psyqo::HelixSelector::Event e) { onEvent(e); });
    // Auto-repeat, the way the tetris example does it: one long-lived periodic
    // timer, never armed or cancelled anywhere else. It ticks at the repeat rate
    // and the initial delay is a subtraction against `m_heldSince`, so there is no
    // second timer and no period juggling. Unsigned subtraction is also what makes
    // the 32-bit microsecond clock rolling over a non-event.
    helix.gpu().armPeriodicTimer(c_repeatRate, [this](uint32_t t) {
        if (m_held == 0) return;
        if ((t - m_heldSince) < c_repeatDelay) return;
        m_selector.step(m_held);
    });
}

void HelixScene::onEvent(psyqo::HelixSelector::Event e) {
    if (e.type != psyqo::HelixSelector::Event::Activated) return;
    m_activations++;
    // Everything below this line is application policy. The selector has no idea
    // that erase, submit or capital letters exist.
    if (e.index == c_eraseIndex) {
        if (m_textLen > 0) m_text[--m_textLen] = 0;
        return;
    }
    if (e.index == c_submitIndex) {
        m_submitted = true;
        return;
    }
    if (m_textLen < sizeof(m_text) - 1) {
        m_text[m_textLen++] = m_upper ? c_items[e.index].upper : c_items[e.index].lower;
        m_text[m_textLen] = 0;
    }
}

void HelixScene::readInput() {
    auto& pad = helix.m_input;
    auto p = psyqo::AdvancedPad::Pad::Pad1a;
    // With nothing plugged in the button word reads as every button held, which
    // is a phantom press on the very first frame, so gate the whole thing.
    if (!pad.isPadConnected(p)) return;

    // Shoulder held means draw capitals. Pure presentation: the selector never
    // hears about this, and the item count does not change.
    m_upper = pad.isButtonPressed(p, psyqo::AdvancedPad::L1) || pad.isButtonPressed(p, psyqo::AdvancedPad::R1);

    // Analog adapter. The stick angle is the cursor angle directly, so this is a
    // dial: point at a spoke and the cursor is there. Stop feeding it when the
    // stick re-centres and the cursor simply stays put.
    // A digital pad still answers getAdc, with a constant that reads as a stick
    // held at one angle, so ask whether the ADC means anything before believing it.
    if (pad.hasAnalog(p)) {
        int32_t sx = int32_t(pad.getAdc(p, 2)) - 128;
        int32_t sy = int32_t(pad.getAdc(p, 3)) - 128;
        if ((sx * sx + sy * sy) > (40 * 40)) m_selector.setStickAngle(psyqo::atan2(sy, sx));
    }

    // D-pad adapter: one item per press.
    bool left = pad.isButtonPressed(p, psyqo::AdvancedPad::Left);
    bool right = pad.isButtonPressed(p, psyqo::AdvancedPad::Right);
    if (left && !m_prevLeft) {
        m_selector.step(-1);
        m_held = -1;
        m_heldSince = helix.gpu().now();
    }
    if (right && !m_prevRight) {
        m_selector.step(1);
        m_held = 1;
        m_heldSince = helix.gpu().now();
    }
    if (!left && !right) m_held = 0;
    m_prevLeft = left;
    m_prevRight = right;

    bool cross = pad.isButtonPressed(p, psyqo::AdvancedPad::Cross);
    if (cross && !m_prevCross) m_selector.activate();
    m_prevCross = cross;
}

void HelixScene::frame() {
    readInput();
    m_selector.update(helix.m_trig);

    helix.gpu().clear({{.r = 10, .g = 6, .b = 24}});

    unsigned selected = m_selector.currentIndex();
    unsigned count = m_selector.visibleCount();
    for (unsigned n = 0; n < count; n++) {
        const auto& slot = m_selector.slot(n);
        const Item& item = c_items[slot.index];
        bool isSelected = slot.index == selected;
        psyqo::Prim::Quad quad(colorFor(item, slot.fade, isSelected));
        quad.setPointA(slot.a).setPointB(slot.b).setPointC(slot.c).setPointD(slot.d);
        helix.gpu().sendPrimitive(quad);
        // The glyph is drawn upright, centred on the point the selector handed back.
        // System font glyphs are 8x16.
        int32_t f = slot.fade.raw();
        if (f > (int32_t(psyqo::FixedPoint<>::scale) / 3)) {
            char text[2] = {m_upper ? item.upper : item.lower, 0};
            psyqo::Vertex at = {{.x = int16_t(slot.glyph.x - 4), .y = int16_t(slot.glyph.y - 8)}};
            helix.m_font.print(helix.gpu(), text, at, {{.r = 255, .g = 255, .b = 255}});
        }
    }

    // The cursor. The app cannot place this unaided, because the inner radius at
    // the cursor angle moves as the helix scales.
    const auto& c = m_selector.cursor();
    psyqo::Prim::Triangle marker(psyqo::Color{{.r = 210, .g = 210, .b = 235}});
    marker.pointA = c.tip;
    marker.pointB = c.left;
    marker.pointC = c.right;
    helix.gpu().sendPrimitive(marker);

    helix.m_font.print(helix.gpu(), m_text, {{.x = 128, .y = 112}}, {{.r = 255, .g = 255, .b = 255}});
    helix.m_font.printf(helix.gpu(), {{.x = 8, .y = 8}}, {{.r = 160, .g = 160, .b = 180}}, "sel %d  vis %d  act %d%s",
                        selected, count, m_activations, m_submitted ? "  SUBMITTED" : "");
}

int main() { return helix.run(); }
