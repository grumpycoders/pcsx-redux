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

#include "options.hh"

#include "tetris.hh"

extern "C" {
#include "modplayer/modplayer.h"
}

void Options::menuUp() {
    if (m_menuEntry == 0) {
        m_menuEntry = 2;
    } else {
        m_menuEntry--;
    }
    g_tetris.m_sound.playClick();
}

void Options::menuDown() {
    if (m_menuEntry == 2) {
        m_menuEntry = 0;
    } else {
        m_menuEntry++;
    }
    g_tetris.m_sound.playClick();
}

void Options::menuLeft() {
    if (m_menuEntry == 0) {
        if (m_musicVolume > 0) {
            m_musicVolume--;
            MOD_SetMusicVolume(m_musicVolume * 260);
            g_tetris.m_sound.playClick();
        }
    } else if (m_menuEntry == 1) {
        if (g_tetris.m_sound.m_volume > 0) {
            g_tetris.m_sound.m_volume--;
            g_tetris.m_sound.playClick();
        }
    }
}

void Options::menuRight() {
    if (m_menuEntry == 0) {
        if (m_musicVolume < 63) {
            m_musicVolume++;
            MOD_SetMusicVolume(m_musicVolume * 260);
            g_tetris.m_sound.playClick();
        }
    } else if (m_menuEntry == 1) {
        if (g_tetris.m_sound.m_volume < 63) {
            g_tetris.m_sound.m_volume++;
            g_tetris.m_sound.playClick();
        }
    }
}

void Options::menuSelect() {
    if (m_menuEntry == 2) {
        m_exitOptions = true;
        g_tetris.m_sound.playClick();
    }
}

void Options::menuBack() {
    m_exitOptions = true;
    g_tetris.m_sound.playClick();
}

void Options::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) {
            switch (event.button) {
                case psyqo::SimplePad::Button::Up:
                    menuUp();
                    break;
                case psyqo::SimplePad::Button::Down:
                    menuDown();
                    break;
                case psyqo::SimplePad::Button::Left:
                    menuLeft();
                    break;
                case psyqo::SimplePad::Button::Right:
                    menuRight();
                    break;
                case psyqo::SimplePad::Button::Cross:
                    menuSelect();
                    break;
                case psyqo::SimplePad::Button::Circle:
                    menuBack();
                    break;
            }
        }
    });
}

void Options::frame() {
    auto& font = g_tetris.m_font;
    auto& gpu = g_tetris.gpu();

    gpu.clear();
    g_tetris.renderTetrisLogo();

    // The selected entry will blink.
    auto c = g_tetris.getBlink(4);
    font.printf(gpu, {{.x = 100, .y = 8 * 16}}, m_menuEntry == 0 ? c : GREY, "Music volume: %d", m_musicVolume);
    font.printf(gpu, {{.x = 100, .y = 9 * 16}}, m_menuEntry == 1 ? c : GREY, "Sound volume: %d",
                g_tetris.m_sound.m_volume);
    font.print(gpu, "Exit", {{.x = 132, .y = 10 * 16}}, m_menuEntry == 2 ? c : GREY);

    // And we display some > < carets around the selected entry.
    int16_t line = 8 * 16 + m_menuEntry * 16;
    font.print(gpu, ">", {{.x = 100 - 8, .y = line}}, WHITE);

    if (m_exitOptions) popScene();
}

void Options::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
