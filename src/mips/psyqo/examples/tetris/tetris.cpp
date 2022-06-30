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
#include "psyqo/graphics.hh"
#include "psyqo/input.hh"
#include "psyqo/music.hh"
#include "psyqo/sound.hh"
#include "psyqo/timer.hh"

namespace {

class Tetris final : public psyqo::Application {
    void prepare() override;
    void frame() override;
    void button(psyqo::Input::Event& event);

    psyqo::Graphics m_graphics;
    psyqo::Input m_input;
    psyqo::Timer m_timer;
    psyqo::Sound m_sound;
    psyqo::Music m_music;
    psyqo::Font m_font;

    uint8_t m_anim = 0;
    bool m_direction = true;
    bool m_systemFontUploaded = false;
};

}  // namespace

void Tetris::prepare() {
    {
        auto config = psyqo::GPU::Configuration();
        config.setResolution(psyqo::GPU::Resolution::W320)
            .setVideoMode(psyqo::GPU::VideoMode::AUTO)
            .setColorMode(psyqo::GPU::ColorMode::C15BITS)
            .setInterlace(false);
        gpu().initialize(config);
    }

    m_input.onEvent([this](auto event) -> void { button(event); });
}

void Tetris::button(psyqo::Input::Event& event) {}

void Tetris::frame() {
    if (!m_systemFontUploaded) {
        m_systemFontUploaded = true;
        m_font.uploadSystemFont(gpu());
    }
    if (m_anim == 0) {
        m_direction = true;
    } else if (m_anim == 255) {
        m_direction = false;
    }
    Color bg{{.r = 0, .g = 64, .b = 91}};
    bg.r = m_anim;
    gpu().clear(bg);
    if (m_direction) {
        m_anim++;
    } else {
        m_anim--;
    }

    Color c = {.r = 0xff, .g = 0xff, .b = 0xff};
    c.b = 255 - m_anim;
    m_font.print(gpu(), "Hello World!", {.x = 16, .y = 32}, c);
}

Tetris tetris;

int main() { return tetris.run(); }
