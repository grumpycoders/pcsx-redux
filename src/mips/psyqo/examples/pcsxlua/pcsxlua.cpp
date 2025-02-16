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

#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

namespace {

// This is a demo application that shows how to use Lua to inspect
// or modify some state inside an application. In this case, we're
// going to modify the background color of the scene in real time.
// The script called `pcsxlua.lua` will be responsible for that,
// and needs to be loaded by the emulator before running this.
// This can be achieved by using the `-dofile pcsxlua.lua` command
// line argument when starting the emulator.
class PCSXLua final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_systemFont;
};

class PCSXLuaScene final : public psyqo::Scene {
    void start(StartReason reason) override;
    void frame() override;
    // This variable will be registered to PCSX in order
    // to be modified in real time from the Lua script.
    psyqo::Color m_bg = {{.r = 0, .g = 64, .b = 91}};
};

PCSXLua pcsxLua;
PCSXLuaScene pcsxLuaScene;

// This will be calling into the Lua script from execSlot 255,
// where it will be able to modify the background color of the scene.
void pcsxRegisterVariable(void* address, const char* name) {
    register void* a0 asm("a0") = address;
    register const char* a1 asm("a1") = name;
    __asm__ volatile("" : : "r"(a0), "r"(a1));
    *((volatile uint8_t* const)0x1f802081) = 255;
}

}  // namespace

void PCSXLua::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void PCSXLua::createScene() {
    m_systemFont.uploadSystemFont(gpu());
    pushScene(&pcsxLuaScene);
}

void PCSXLuaScene::start(StartReason reason) {
    if (reason == StartReason::Create) {
        pcsxRegisterVariable(&m_bg, "pcsxLuaScene.m_bg");
    }
}

void PCSXLuaScene::frame() {
    pcsxLua.gpu().clear(m_bg);

    psyqo::Color c = {{.r = 255, .g = 255, .b = uint8_t(255)}};
    pcsxLua.m_systemFont.print(pcsxLua.gpu(), "Hello World!", {{.x = 16, .y = 32}}, c);
}

int main() { return pcsxLua.run(); }
