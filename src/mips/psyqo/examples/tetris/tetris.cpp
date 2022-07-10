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
#include "psyqo/simplepad.hh"
#include "psyqo/scene.hh"

namespace {

class Tetris final : public psyqo::Application {
    void prepare() override;
    void createScene() override;
    void button(psyqo::SimplePad::Event& event);

    psyqo::SimplePad m_input;
    psyqo::Font<> m_font;
};

class SplashScreen final : public psyqo::Scene {
    void frame() override;
};

Tetris tetris;
SplashScreen splashScreen;

}  // namespace

void Tetris::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);

    m_input.setOnEvent([this](auto event) -> void { button(event); });
}

void Tetris::button(psyqo::SimplePad::Event& event) {}

void Tetris::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&splashScreen);
}

void SplashScreen::frame() {}

int main() { return tetris.run(); }
