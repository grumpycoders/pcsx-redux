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

#include "mainmenu.hh"

#include "tetris.hh"

void MainMenu::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) {
            switch (event.button) {
                case psyqo::SimplePad::Button::Start:
                    m_startPressed = true;
                    break;
                case psyqo::SimplePad::Button::Up:
                    menuUp();
                    break;
                case psyqo::SimplePad::Button::Down:
                    menuDown();
                    break;
            }
        }
    });
}

void MainMenu::menuUp() {
    if (m_menuEntry > 0) {
        m_menuEntry--;
    }
}

void MainMenu::menuDown() {
    if (m_menuEntry < 2) {
        m_menuEntry++;
    }
}

void MainMenu::render(psyqo::GPU& gpu) {
    auto& font = g_tetris.m_font;
    gpu.clear();
    g_tetris.renderTetrisLogo(gpu);
    auto c = g_tetris.getBlink(gpu, 4);
    font.print(gpu, "Start", {{.x = 140, .y = 8 * 16}}, m_menuEntry == 0 ? c : GREY);
    font.print(gpu, "Options", {{.x = 132, .y = 9 * 16}}, m_menuEntry == 1 ? c : GREY);
    font.print(gpu, "Credits", {{.x = 132, .y = 10 * 16}}, m_menuEntry == 2 ? c : GREY);
    int16_t line = 8 * 16 + m_menuEntry * 16;
    font.print(gpu, ">", {{.x = 124, .y = line}}, WHITE);
    font.print(gpu, "<", {{.x = 188, .y = line}}, WHITE);
}

void MainMenu::frame() {
    render(g_tetris.gpu());

    if (m_startPressed) {
        m_startPressed = false;
        switch (m_menuEntry) {
            case 0:
                pushScene(&g_tetris.m_mainGame);
                break;
            case 1:
                pushScene(&g_tetris.m_options);
                break;
            case 2:
                pushScene(&g_tetris.m_credits);
                break;
        }
    }
}

void MainMenu::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
