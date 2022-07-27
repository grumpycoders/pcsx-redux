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

#include "credits.hh"

#include "constants.hh"
#include "tetris.hh"

void Credits::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) m_leave = true;
    });
}

void Credits::frame() {
    auto& gpu = g_tetris.gpu();
    auto& font = g_tetris.m_font;
    gpu.clear();
    font.print(gpu, "Tetris PSYQo example", {{.x = 20 * 4, .y = 1 * 16}}, WHITE);
    font.print(gpu, "PCSX-Redux project", {{.x = 22 * 4, .y = 2 * 16}}, WHITE);
    font.print(gpu, "https://bit.ly/pcsx-redux", {{.x = 15 * 4, .y = 3 * 16}}, WHITE);

    font.print(gpu, "Written by Nicolas 'Pixel' Noble", {{.x = 8 * 4, .y = 5 * 16}}, WHITE);
    font.print(gpu, "Music by m0d", {{.x = 28 * 4, .y = 6 * 16}}, WHITE);
    font.print(gpu, "Sound effects by Sickle", {{.x = 17 * 4, .y = 7 * 16}}, WHITE);

    if (m_leave) {
        g_tetris.m_sound.playClick();
        m_leave = false;
        popScene();
    }
}

void Credits::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
