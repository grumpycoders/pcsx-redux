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
#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"

namespace {

class Timers final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<1> m_font;
    psyqo::SimplePad m_input;
    bool m_paused = false;
};

class TimersScene final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;
    uintptr_t m_timerId;
    unsigned m_fasterCounter = 0;
};

class TimersPausedScene final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;
};

Timers timers;
TimersScene timersScene;
TimersPausedScene timersPausedScene;

}  // namespace

void Timers::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Timers::createScene() {
    m_font.uploadSystemFont(gpu());
    m_input.initialize();
    pushScene(&timersScene);
}

void TimersScene::start(Scene::StartReason reason) {
    timers.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Start) timers.m_paused = true;
    });
    if (reason == Scene::StartReason::Create) {
        m_timerId = timers.gpu().armPeriodicTimer(500'000, [this](auto) { m_fasterCounter++; });
    } else {
        timers.gpu().pauseTimer(m_timerId);
    }
}

void TimersScene::frame() {
    timers.gpu().clear();
    uint32_t now = timers.gpu().now() / 10000;
    uint32_t frac = now % 100;
    uint32_t secs = now / 100;
    auto c = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    timers.m_font.printf(timers.gpu(), {{.x = 64, .y = 32}}, c, "%i.%02i", secs, frac);
    timers.m_font.printf(timers.gpu(), {{.x = 64, .y = 64}}, c, "Half-secs: %i", m_fasterCounter);
    if (timers.m_paused) pushScene(&timersPausedScene);
}

void TimersScene::teardown(Scene::TearDownReason reason) {
    timers.m_input.setOnEvent(nullptr);
    if (reason == Scene::TearDownReason::Destroy) {
        timers.gpu().cancelTimer(m_timerId);
    } else {
        timers.gpu().resumeTimer(m_timerId);
    }
}

void TimersPausedScene::start(Scene::StartReason reason) {
    timers.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Start) timers.m_paused = false;
    });
}

void TimersPausedScene::frame() {
    timers.gpu().clear();
    timers.m_font.printf(timers.gpu(), {{.x = 64, .y = 32}}, {{.r = 255, .g = 255, .b = 255}}, "Paused");
    if (!timers.m_paused) popScene();
}

void TimersPausedScene::teardown(Scene::TearDownReason reason) { timers.m_input.setOnEvent(nullptr); }

int main() { return timers.run(); }
