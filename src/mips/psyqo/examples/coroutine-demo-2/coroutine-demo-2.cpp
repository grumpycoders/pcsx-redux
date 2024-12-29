/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include <EASTL/fixed_string.h>

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/coroutine.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/kernel.hh"
#include "psyqo/scene.hh"
#include "psyqo/xprintf.h"

namespace {

class CoroutineDemo2 final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
};

class CoroutineDemoScene final : public psyqo::Scene {
    void frame() override;
    void start(StartReason reason) override;
    psyqo::Coroutine<> coroutine();
    psyqo::Coroutine<int> subcoroutine(int, int);
    psyqo::Coroutine<> m_coroutine;
    eastl::fixed_string<char, 256> m_text;
};

CoroutineDemo2 coroutineDemo2;
CoroutineDemoScene coroutineDemoScene;

}  // namespace

void CoroutineDemo2::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void CoroutineDemo2::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&coroutineDemoScene);
}

void CoroutineDemoScene::start(StartReason reason) {
    psyqo::Kernel::assert(reason == StartReason::Create, "Wrong internal state");
    m_coroutine = coroutine();
    m_coroutine.resume();
}

using namespace psyqo::timer_literals;

psyqo::Coroutine<> CoroutineDemoScene::coroutine() {
    m_text = "Coroutine... sleeping for 2s";
    co_await gpu().delay(2_s);
    m_text = "Waking up... sleeping for 1s";
    co_await gpu().delay(1_s);
    m_text = "Waking up... sleeping again for 1s";
    co_await gpu().delay(1_s);
    m_text = "Waking up... sleeping for 5s this time";
    co_await gpu().delay(5_s);
    int r = co_await subcoroutine(3, 4);
    fsprintf(m_text, "Subcoroutine returned %d", r);
    co_return;
}

psyqo::Coroutine<int> CoroutineDemoScene::subcoroutine(int a, int b) {
    m_text = "Subcoroutine... sleeping for 2s";
    co_await gpu().delay(2_s);
    co_return a + b;
}

void CoroutineDemoScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    coroutineDemo2.gpu().clear(bg);
    auto c = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    coroutineDemo2.m_font.print(coroutineDemo2.gpu(), m_text, {{.x = 4, .y = 32}}, c);
}

int main() { return coroutineDemo2.run(); }
