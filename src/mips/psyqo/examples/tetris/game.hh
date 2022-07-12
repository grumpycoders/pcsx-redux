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

#pragma once

#include "psyqo/application.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/scene.hh"

static constexpr psyqo::Color HIRED = {{.r = 120, .g = 0, .b = 0}};
static constexpr psyqo::Color HIORANGE = {{.r = 120, .g = 80, .b = 0}};
static constexpr psyqo::Color HIYELLOW = {{.r = 120, .g = 120, .b = 0}};
static constexpr psyqo::Color HIGREEN = {{.r = 0, .g = 120, .b = 0}};
static constexpr psyqo::Color HIBLUE = {{.r = 0, .g = 0, .b = 120}};
static constexpr psyqo::Color HICYAN = {{.r = 0, .g = 120, .b = 120}};
static constexpr psyqo::Color HIPURPLE = {{.r = 80, .g = 0, .b = 120}};
static constexpr psyqo::Color RED = {{.r = 90, .g = 41, .b = 42}};
static constexpr psyqo::Color ORANGE = {{.r = 105, .g = 80, .b = 52}};
static constexpr psyqo::Color YELLOW = {{.r = 118, .g = 112, .b = 79}};
static constexpr psyqo::Color GREEN = {{.r = 69, .g = 88, .b = 49}};
static constexpr psyqo::Color BLUE = {{.r = 38, .g = 64, .b = 101}};
static constexpr psyqo::Color CYAN = {{.r = 51, .g = 97, .b = 105}};
static constexpr psyqo::Color PURPLE = {{.r = 103, .g = 69, .b = 101}};
static constexpr psyqo::Color WHITE = {{.r = 255, .g = 255, .b = 255}};
static constexpr psyqo::Color GREY = {{.r = 80, .g = 80, .b = 80}};
static constexpr psyqo::Color BLACK = {{.r = 0, .g = 0, .b = 0}};

extern psyqo::Application* g_tetrisApplication;
extern const uint8_t PIECES[7][4][4][4];

class MainGame final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;
};
