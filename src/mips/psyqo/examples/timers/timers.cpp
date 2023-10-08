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

// This example goes a little bit over the top, but it's a good example of
// how to use the PSYQo library. The Pause scene probably is overkill, and
// should rather be handled by the same scene, but this way we're properly
// showing a scene transition and the passage of callbacks.

namespace {

class Timers final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<1> m_font;
    psyqo::SimplePad m_input;
    bool m_initialized = false;
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

// As usual, we're initializing the GPU and only the GPU in the `prepare` method of the
// whole application.
void Timers::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

// We're going to use pads to control the application. We'll use the `SimplePad` class
// which needs to be initialized here.
void Timers::createScene() {
    // Even though our logic isn't meant to be exiting our root scene, we're going to
    // show how to properly protect against such case.
    if (!m_initialized) {
        m_font.uploadSystemFont(gpu());
        m_input.initialize();
        m_initialized = true;
    }
    // We only have one root scene, so just push it. One case where this can be
    // useful is a "return to menu" which simply pops all of the scenes until it
    // reaches `nullptr`, thus allowing the logic to be properly destroyed and
    // re-created from scratch.
    pushScene(&timersScene);
}

void TimersScene::start(Scene::StartReason reason) {
    // When our root scene begins, we're going to capture pad input.
    // Our only reaction here will be to pause the application when
    // the user presses the `Start` button.
    timers.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        // Note that we _could_ use `pushScene` here, but we'd be at risk of
        // destroying the current lambda that's being executed, leading to
        // memory corruption, if the compiler doesn't optimize it with a tail
        // call.
        if (event.button == psyqo::SimplePad::Start) timers.m_paused = true;
    });
    if (reason == Scene::StartReason::Create) {
        // If we are getting created, create a 500ms periodic timer too.
        using namespace psyqo::timer_literals;
        m_timerId = timers.gpu().armPeriodicTimer(500_ms, [this](auto) { m_fasterCounter++; });
    } else {
        // Otherwise, if we're getting resumed, we're going to resume our timer.
        timers.gpu().resumeTimer(m_timerId);
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
    // The application is paused when the user presses the `Start` button. We are delegating
    // pushing the Pause scene here to avoid potential memory corruption within the pad callback.
    if (timers.m_paused) pushScene(&timersPausedScene);
}

void TimersScene::teardown(Scene::TearDownReason reason) {
    // When we're no longer the main scene, remove the pad callback.
    timers.m_input.setOnEvent(nullptr);
    if (reason == Scene::TearDownReason::Destroy) {
        // If we're being popped out (which shouldn't happen due to the way our scene
        // logic currently is setup), we're going to destroy our timer.
        timers.gpu().cancelTimer(m_timerId);
    } else {
        // Otherwise, this means we're being paused, so we're going to pause our timer.
        timers.gpu().pauseTimer(m_timerId);
    }
}

void TimersPausedScene::start(Scene::StartReason reason) {
    // The Paused scene only wants to unpause the application, so it's doing
    // the same logic as the root scene, but to set `m_paused` to false instead.
    timers.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
        if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
        if (event.button == psyqo::SimplePad::Start) timers.m_paused = false;
    });
}

void TimersPausedScene::frame() {
    timers.gpu().clear();
    timers.m_font.printf(timers.gpu(), {{.x = 64, .y = 32}}, {{.r = 255, .g = 255, .b = 255}}, "Paused");
    // Similarly to the root scene, we're going to change the scene during `frame`
    // instead of the pad callback.
    if (!timers.m_paused) popScene();
}

void TimersPausedScene::teardown(Scene::TearDownReason reason) { timers.m_input.setOnEvent(nullptr); }

int main() { return timers.run(); }
