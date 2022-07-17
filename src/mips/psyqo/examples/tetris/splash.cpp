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

#include "splash.hh"

#include "tetris.hh"

// The only thing we'll do on the splash screen is to
// wait for the user to press the start button.
// So this is the only thing we'll monitor.
void SplashScreen::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) {
            if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
            if (event.button == psyqo::SimplePad::Button::Start) {
                // Note that we don't switch scenes here, but only set
                // a boolean to switch scenes during the next call to
                // `frame()`. We want to change as little environment
                // as possible during callbacks.
                m_startPressed = true;
            }
        }
    });
}

void SplashScreen::frame() {
    auto& gpu = g_tetris.gpu();
    auto& font = g_tetris.m_font;
    // First, clear the screen.
    gpu.clear();
    // Now, draw the tetris logo.
    g_tetris.renderTetrisLogo();

    // And finally, draw the "Press start" message,
    // roughly in the middle of the screen. It will
    // blink on a 1 second period.
    font.print(gpu, "Press start", {{.x = 115, .y = 7 * 16}}, g_tetris.getBlink());

    // Finally, if the user pressed the start button,
    // we'll switch to the main menu.
    if (m_startPressed) {
        m_startPressed = false;
        pushScene(&g_tetris.m_mainMenu);
        g_tetris.m_sound.playClick();
    }
}

// When the splash screen is no longer the top scene,
// then we no longer want to listen to the input events.
void SplashScreen::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
