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

#include "pause.hh"

#include "constants.hh"
#include "tetris.hh"

// The only thing we care about input-wise during this scene is when the
// user presses the start button to unpause the game, which will pop the scene.
// But upon this scene's startup, we will also hide the playfield by calling
// its `emptyFragments` method.
void Pause::start(Scene::StartReason reason) {
    g_tetris.m_playfield.emptyFragments();
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Start) m_unpause = true;
    });
}

void Pause::frame() {
    // The MainGame scene exposes its `render` method, so we just call it
    // to get the playfield and its various information rendered.
    g_tetris.m_mainGame.render();

    // We also want to render the pause message in addition to the main game.
    g_tetris.m_font.print(g_tetris.gpu(), "PAUSED", {{.x = 0, .y = 2 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "Press", {{.x = 0, .y = 4 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "Start", {{.x = 0, .y = 5 * 16}}, WHITE);
    g_tetris.m_font.print(g_tetris.gpu(), "to unpause", {{.x = 0, .y = 6 * 16}}, WHITE);

    // If the user has pressed the start button, we will pop the scene.
    if (m_unpause) {
        m_unpause = false;
        popScene();
    }
}

// When the scene is torn down, we want to unhide the playfield, and stop
// listening for button input.
void Pause::teardown(Scene::TearDownReason reason) {
    g_tetris.m_playfield.restoreFragments();
    g_tetris.m_input.setOnEvent(nullptr);
}
