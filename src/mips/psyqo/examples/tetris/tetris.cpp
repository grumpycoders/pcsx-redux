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
#include "game.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/rectangles.hh"
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"

Tetris g_tetris;

namespace {

class SplashScreen final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;

    bool m_startPressed = false;
};

class MainMenu final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;

    void menuUp();
    void menuDown();
    void render(psyqo::GPU&);

    bool m_startPressed = false;
    unsigned m_menuEntry = 0;
};

class Options final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;

    void menuUp();
    void menuDown();

    bool m_startPressed = false;
};

class Credits final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;

    bool m_leave = false;
};

SplashScreen s_splashScreen;
MainMenu s_mainMenu;
Options s_options;
Credits s_credits;
MainGame s_mainGame;

}  // namespace

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
    }
    pushScene(&s_splashScreen);
}

void SplashScreen::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) {
            if (event.button == psyqo::SimplePad::Button::Start) {
                m_startPressed = true;
            }
        }
    });
}

static void renderTetrisLogo(psyqo::GPU& gpu) {
    auto& font = g_tetris.m_font;

    font.print(gpu, "T", {{.x = 17 * 8, .y = 5 * 16}}, RED);
    font.print(gpu, "E", {{.x = 18 * 8, .y = 5 * 16}}, ORANGE);
    font.print(gpu, "T", {{.x = 19 * 8, .y = 5 * 16}}, YELLOW);
    font.print(gpu, "R", {{.x = 20 * 8, .y = 5 * 16}}, GREEN);
    font.print(gpu, "I", {{.x = 21 * 8, .y = 5 * 16}}, CYAN);
    font.print(gpu, "S", {{.x = 22 * 8, .y = 5 * 16}}, PURPLE);

    font.print(gpu, "T", {{.x = 17 * 8 - 1, .y = 5 * 16 - 1}}, HIRED);
    font.print(gpu, "E", {{.x = 18 * 8 - 1, .y = 5 * 16 - 1}}, HIORANGE);
    font.print(gpu, "T", {{.x = 19 * 8 - 1, .y = 5 * 16 - 1}}, HIYELLOW);
    font.print(gpu, "R", {{.x = 20 * 8 - 1, .y = 5 * 16 - 1}}, HIGREEN);
    font.print(gpu, "I", {{.x = 21 * 8 - 1, .y = 5 * 16 - 1}}, HICYAN);
    font.print(gpu, "S", {{.x = 22 * 8 - 1, .y = 5 * 16 - 1}}, HIPURPLE);
}

static psyqo::Color getBlink(psyqo::GPU& gpu, unsigned scale = 1) {
    psyqo::Color c;
    uint32_t time = scale * gpu.getFrameCount() / gpu.getRefreshRate();
    if ((time & 1) == 0) {
        c = WHITE;
    } else {
        c = GREY;
    }
    return c;
}

void SplashScreen::frame() {
    auto& gpu = g_tetris.gpu();
    auto& font = g_tetris.m_font;
    gpu.clear();
    renderTetrisLogo(gpu);

    font.print(gpu, "Press start", {{.x = 115, .y = 7 * 16}}, getBlink(gpu));

    if (m_startPressed) {
        m_startPressed = false;
        pushScene(&s_mainMenu);
    }
}

void SplashScreen::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }

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
    renderTetrisLogo(gpu);
    auto c = getBlink(gpu, 4);
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
                pushScene(&s_mainGame);
                break;
            case 1:
                pushScene(&s_options);
                break;
            case 2:
                pushScene(&s_credits);
                break;
        }
    }
}

void MainMenu::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }

void Credits::start(Scene::StartReason reason) {
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type == psyqo::SimplePad::Event::ButtonReleased) m_leave = true;
    });
}

void Credits::frame() {
    auto& gpu = g_tetris.gpu();
    auto& font = g_tetris.m_font;
    font.print(gpu, "TBD", {{.x = 0, .y = 0}}, WHITE);

    if (m_leave) {
        m_leave = false;
        popScene();
    }
}

void Credits::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }

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

void Options::menuUp() {}
void Options::menuDown() {}

void Options::frame() { popScene(); }

void Options::teardown(Scene::TearDownReason reason) { g_tetris.m_input.setOnEvent(nullptr); }

int main() { return g_tetris.run(); }
