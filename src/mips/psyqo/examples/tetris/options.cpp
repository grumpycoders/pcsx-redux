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

void Options::menuUp() {}
void Options::menuDown() {}

void Options::start(Scene::StartReason reason) {
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

void Options::frame() { popScene(); }

void Options::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }
