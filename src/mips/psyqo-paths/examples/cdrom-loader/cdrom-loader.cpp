/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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
#include "psyqo/cdrom-device.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/iso9660-parser.hh"
#include "psyqo/scene.hh"
#include "psyqo-paths/cdrom-loader.hh"

namespace {

class CDRomLoaderExample final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::CDRomDevice m_cdrom;
    psyqo::ISO9660Parser m_isoParser = psyqo::ISO9660Parser(&m_cdrom);
    psyqo::paths::CDRomLoader m_cdromLoader;
    eastl::vector<uint8_t> m_buffer;
    bool m_callbackCalled = false;
};

class CDRomLoaderExampleScene final : public psyqo::Scene {
    void frame() override;
};

CDRomLoaderExample cdromLoaderExample;
CDRomLoaderExampleScene cdromLoaderExampleScene;

}  // namespace

void CDRomLoaderExample::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_cdrom.prepare();
}

void CDRomLoaderExample::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&cdromLoaderExampleScene);
    m_cdromLoader.readFile("SYSTEM.CNF;1", cdromLoaderExample.gpu(), cdromLoaderExample.m_isoParser,
                           [this](eastl::vector<uint8_t>&& buffer) {
        m_buffer = eastl::move(buffer);
        m_callbackCalled = true;
    });
}

void CDRomLoaderExampleScene::frame() {
    auto& gpu = cdromLoaderExample.gpu();
    gpu.clear({{.r = 0, .g = 64, .b = 91}});
    if (cdromLoaderExample.m_callbackCalled) {
        cdromLoaderExample.m_font.printf(gpu, {{.x = 16, .y = 32}}, {{.r = 255, .g = 255, .b = 255}}, "Read %i bytes",
                                         cdromLoaderExample.m_buffer.size());
    } else {
        cdromLoaderExample.m_font.printf(gpu, {{.x = 16, .y = 32}}, {{.r = 255, .g = 255, .b = 255}}, "Loading...");
    }
}

int main() { return cdromLoaderExample.run(); }
