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
#include "psyqo/cdrom-device.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

namespace {

class CDRomDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::CDRomDevice m_cdrom;
    uint8_t m_buffer[2048];
};

class CDRomDemoScene final : public psyqo::Scene {
    void frame() override;
};

// We're instantiating the two objects above right now.
CDRomDemo cdromDemo;
CDRomDemoScene cdromDemoScene;

}  // namespace

void CDRomDemo::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_cdrom.prepare();
}

void CDRomDemo::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&cdromDemoScene);
    m_cdrom.readSectors(16, 1, m_buffer, [this](bool success) {
        if (success) {
            ramsyscall_printf("Success: %02x %02x %02x %02x %02x %02x %02x %02x\n", m_buffer[0], m_buffer[1],
                              m_buffer[2], m_buffer[3], m_buffer[4], m_buffer[5], m_buffer[6], m_buffer[7]);
        } else {
            syscall_puts("Failure\n");
        }
    });
}

void CDRomDemoScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    cdromDemo.gpu().clear(bg);
}

int main() { return cdromDemo.run(); }
