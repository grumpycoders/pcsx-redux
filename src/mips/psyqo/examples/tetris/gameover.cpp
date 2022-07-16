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

#include "gameover.hh"

#include "tetris.hh"

// The `GameOver` scene works extremely similarly to the `Pause` scene.
void GameOver::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Start) m_unpause = true;
    });
}

void GameOver::frame() {
    g_tetris.m_mainGame.render();
    g_tetris.m_font.print(g_tetris.gpu(), "GAME OVER", {{.x = 0, .y = 2 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "Press", {{.x = 0, .y = 4 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "Start", {{.x = 0, .y = 5 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "to exit", {{.x = 0, .y = 6 * 16}}, WHITE);
    if (m_unpause) {
        m_unpause = false;
        // The main difference with the Pause scene is we pop all the scenes,
        // not just the current one. This will force the application to
        // re-create the root scene.
        while (popScene())
            ;
    }
}

void GameOver::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
