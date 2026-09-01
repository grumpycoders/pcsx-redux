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

#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/misc.hh"
#include "psyqo/scene.hh"

namespace {

// This is the same hello world example, but using chained DMA calls
// instead of the normal immediate calls. Only the difference is
// going to be documented throughout this file.
class HelloChained final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_systemFont;
    psyqo::Font<> m_romFont;
};

class HelloChainedScene final : public psyqo::Scene {
    void frame() override;

    uint8_t m_anim = 0;
    bool m_direction = true;

    // We need two FastFill fragments to hold our clear commands
    // while double buffering. We can't use the same fragment
    // for two frames in a row, because the GPU will still be
    // processing the previous frame's commands.
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_clear[2];
};

HelloChained helloChained;
HelloChainedScene helloChainedScene;

}  // namespace

void HelloChained::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void HelloChained::createScene() {
    m_systemFont.uploadSystemFont(gpu());
    m_romFont.uploadKromFont(gpu(), {{.x = 960, .y = int16_t(512 - 48 - 90)}});
    pushScene(&helloChainedScene);
}

void HelloChainedScene::frame() {
    if (m_anim == 0) {
        m_direction = true;
    } else if (m_anim == 255) {
        m_direction = false;
    }
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    bg.r = m_anim;
    // We need to get the current parity to know which fragment to use
    // from our double buffer.
    auto parity = gpu().getParity();
    // Get a reference to the fragment we're going to use this frame
    // to clear the screen.
    auto& clear = m_clear[parity];
    // We're currently computing the next frame that'll be drawn by
    // the GPU, while the GPU is still processing the previous frame.
    // Therefore, we need to grab the next clear command from the GPU
    // and chain it.
    gpu().getNextClear(clear.primitive, bg);
    gpu().chain(clear);

    if (m_direction) {
        m_anim++;
    } else {
        m_anim--;
    }

    psyqo::Color c = {{.r = 255, .g = 255, .b = uint8_t(255 - m_anim)}};
    // Finally, chain some text to be printed on the screen. Each
    // Font<> object has its own set of fragments. The default is 16,
    // which means 8 text fragments can be displayed per frame. If
    // more than 8 fragments are chained, there will be corruption.
    // More fragments can be added by increasing the template parameter
    // of the Font<> object.
    helloChained.m_systemFont.chainprint(gpu(), "Hello World!", {{.x = 16, .y = 32}}, c);
    helloChained.m_romFont.chainprint(gpu(), "Hello World!", {{.x = 16, .y = 64}}, c);
}

int main() { return helloChained.run(); }
