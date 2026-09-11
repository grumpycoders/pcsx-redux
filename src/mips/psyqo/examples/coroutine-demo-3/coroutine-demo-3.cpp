/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include <EASTL/string.h>

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/coroutine.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/kernel.hh"
#include "psyqo/scene.hh"
#include "psyqo/xprintf.h"

namespace {

class CoroutineDemo3 final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
};

class CoroutineDemoScene final : public psyqo::Scene {
    void frame() override;
    void start(StartReason reason) override;
    void coroutine();
    psyqo::Stackful<65536> m_coroutine;
    eastl::string m_text;
};

CoroutineDemo3 coroutineDemo3;
CoroutineDemoScene coroutineDemoScene;

}  // namespace

void CoroutineDemo3::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void CoroutineDemo3::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&coroutineDemoScene);
}

void CoroutineDemoScene::start(StartReason reason) {
    psyqo::Kernel::assert(reason == StartReason::Create, "Wrong internal state");
    m_coroutine.initialize([this]() { coroutine(); });
    m_coroutine.resume();
}

void CoroutineDemoScene::coroutine() {
    using namespace psyqo::timer_literals;
    m_text = "Coroutine... sleeping for 2s";
    gpu().armTimer(gpu().now() + 2_s, [this](uint32_t) {
        m_text = "Coroutine... waking up";
        m_coroutine.resume();
    });
    m_coroutine.yield();
    m_text = "Waking up... sleeping for 1s";
    gpu().armTimer(gpu().now() + 1_s, [this](uint32_t) {
        m_text = "Waking up... sleeping for 5s this time";
        m_coroutine.resume();
    });
    m_coroutine.yield();
    m_text = "Waking up... sleeping again for 1s";
    gpu().armTimer(gpu().now() + 1_s, [this](uint32_t) {
        m_text = "Waking up... sleeping for 5s this time";
        m_coroutine.resume();
    });
    m_coroutine.yield();
    m_text = "Waking up... sleeping for 5s this time";
    gpu().armTimer(gpu().now() + 5_s, [this](uint32_t) {
        m_text = "All done.";
        m_coroutine.resume();
    });
    m_coroutine.yield();
}

void CoroutineDemoScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    coroutineDemo3.gpu().clear(bg);
    auto c = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    coroutineDemo3.m_font.print(coroutineDemo3.gpu(), m_text, {{.x = 4, .y = 32}}, c);
}

int main() { return coroutineDemo3.run(); }
