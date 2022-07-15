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

#include "tetris.hh"

Tetris g_tetris;

int main() { return g_tetris.run(); }

void Tetris::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Tetris::createScene() {
    if (!m_initialized) {
        m_font.uploadSystemFont(gpu());
        m_input.initialize();
        m_initialized = true;
    }
    pushScene(&m_splash);
}

void Tetris::renderTetrisLogo() {
    auto& font = m_font;

    font.print(gpu(), "T", {{.x = 17 * 8, .y = 5 * 16}}, RED);
    font.print(gpu(), "E", {{.x = 18 * 8, .y = 5 * 16}}, ORANGE);
    font.print(gpu(), "T", {{.x = 19 * 8, .y = 5 * 16}}, YELLOW);
    font.print(gpu(), "R", {{.x = 20 * 8, .y = 5 * 16}}, GREEN);
    font.print(gpu(), "I", {{.x = 21 * 8, .y = 5 * 16}}, CYAN);
    font.print(gpu(), "S", {{.x = 22 * 8, .y = 5 * 16}}, PURPLE);

    font.print(gpu(), "T", {{.x = 17 * 8 - 1, .y = 5 * 16 - 1}}, HIRED);
    font.print(gpu(), "E", {{.x = 18 * 8 - 1, .y = 5 * 16 - 1}}, HIORANGE);
    font.print(gpu(), "T", {{.x = 19 * 8 - 1, .y = 5 * 16 - 1}}, HIYELLOW);
    font.print(gpu(), "R", {{.x = 20 * 8 - 1, .y = 5 * 16 - 1}}, HIGREEN);
    font.print(gpu(), "I", {{.x = 21 * 8 - 1, .y = 5 * 16 - 1}}, HICYAN);
    font.print(gpu(), "S", {{.x = 22 * 8 - 1, .y = 5 * 16 - 1}}, HIPURPLE);
}

psyqo::Color Tetris::getBlink(unsigned scale) {
    psyqo::Color c;
    uint32_t time = scale * gpu().getFrameCount() / gpu().getRefreshRate();
    if ((time & 1) == 0) {
        c = WHITE;
    } else {
        c = GREY;
    }
    return c;
}
