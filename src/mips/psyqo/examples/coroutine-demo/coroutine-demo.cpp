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

#include <EASTL/fixed_string.h>

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/cdrom-device.hh"
#include "psyqo/coroutine.hh"
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/iso9660-parser.hh"
#include "psyqo/scene.hh"
#include "psyqo/xprintf.h"

namespace {

class CoroutineDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::CDRomDevice m_cdrom;
    psyqo::ISO9660Parser m_isoParser = psyqo::ISO9660Parser(&m_cdrom);
    psyqo::ISO9660Parser::ReadRequest m_request;
    eastl::fixed_string<char, 256> m_text;
    psyqo::Coroutine<> m_coroutine;
    uint8_t m_buffer[2048];
    uint32_t m_systemCnfSize = 0;
};

psyqo::Coroutine<> coroutine(CoroutineDemo *demo) {
    syscall_puts("Starting CD-Rom coroutine...\n");
    auto *coroutine = &demo->m_coroutine;
    psyqo::Coroutine<>::Awaiter awaiter = coroutine->awaiter();
    bool success = false;
    bool doneOnce = false;
    using namespace psyqo::timer_literals;
    while (!success) {
        if (doneOnce) {
            demo->gpu().armTimer(demo->gpu().now() + 1_s, [coroutine](auto) { coroutine->resume(); });
            co_await awaiter;
        }
        doneOnce = true;
        demo->m_text = "Resetting CD-Rom controller...";
        syscall_puts("Resetting CD-Rom controller...\n");
        demo->m_cdrom.reset([coroutine, &success](bool s) {
            success = s;
            coroutine->resume();
        });
        co_await awaiter;
        if (!success) {
            demo->m_text = "Controller reset failed, retrying...";
            syscall_puts("Failed. Retrying...\n");
        }
    }
    syscall_puts("Success. Initializing ISO9660 parser and looking for files.\n");
    success = false;
    doneOnce = false;
    while (true) {
        if (doneOnce) {
            demo->gpu().armTimer(demo->gpu().now() + 1_s, [coroutine](auto) { coroutine->resume(); });
            co_await awaiter;
        }
        doneOnce = true;
        demo->m_text = "Reading CD-Rom...";
        demo->m_isoParser.initialize([coroutine, &success](bool s) {
            success = s;
            coroutine->resume();
        });
        co_await awaiter;

        if (!success) {
            demo->m_text = "CD-Rom failed reading, retrying...";
            syscall_puts("ISO9660 parser failed to initialize - wrong CD, damaged CD, or no CD present\n");
            continue;
        }

        syscall_puts("ISO9660 parser initialized successfully, looking for SYSTEM.CNF;1...\n");
        psyqo::ISO9660Parser::DirEntry entry;
        demo->m_isoParser.getDirentry("SYSTEM.CNF;1", &entry, [coroutine, &success](bool s) {
            success = s;
            coroutine->resume();
        });
        co_await awaiter;

        if (!success) {
            demo->m_text = "CD-Rom failed reading, retrying...";
            syscall_puts("ISO9660 parser failed to read disc to locate SYSTEM.CNF;1 - damaged CD ?\n");
            continue;
        }

        demo->m_text = "Reading CD-Rom...";
        eastl::fixed_string<char, 64> exename = "PSX.EXE;1";
        if (entry.type != psyqo::ISO9660Parser::DirEntry::FILE) {
            syscall_puts("SYSTEM.CNF;1 file not found...\n");
            demo->m_systemCnfSize = 0;
        } else {
            syscall_puts("SYSTEM.CNF;1 file found, reading...\n");
            demo->m_cdrom.readSectors(entry.LBA, 1, demo->m_buffer, [coroutine, &success](bool s) {
                success = s;
                coroutine->resume();
            });
            co_await awaiter;
            if (!success) {
                demo->m_text = "CD-Rom failed reading, retrying...";
                syscall_puts("Failed to read system.cnf - damaged CD ?\n");
                continue;
            }
            demo->m_systemCnfSize = eastl::min(entry.size, uint32_t(2048u));
            eastl::string_view systemcnf{reinterpret_cast<const char *>(demo->m_buffer), demo->m_systemCnfSize};
            syscall_puts("SYSTEM.CNF;1 file read, parsing...\n");

            while (!systemcnf.empty()) {
                auto pos = systemcnf.find_first_of("\r\n");
                if (pos == eastl::string_view::npos) {
                    pos = systemcnf.length();
                }
                auto line = systemcnf.substr(0, pos);
                systemcnf.remove_prefix(pos);
                while (!systemcnf.empty() && ((systemcnf[0] == '\r') || (systemcnf[0] == '\n'))) {
                    systemcnf.remove_prefix(1);
                }

                if (line.substr(0, 4) == "BOOT") {
                    line.remove_prefix(4);
                    while (!line.empty() && line[0] == ' ') line.remove_prefix(1);
                    if (line.empty()) continue;
                    if (line[0] != '=') continue;
                    line.remove_prefix(1);
                    while (!line.empty() && line[0] == ' ') line.remove_prefix(1);
                    if (line.empty()) continue;
                    if (line.substr(0, 6) == "cdrom:") line.remove_prefix(6);
                    exename.clear();
                    exename.append(line.data(), line.length());
                    break;
                }
            }
        }

        for (auto &c : exename) {
            if (c == '\\') c = '/';
        }

        ramsyscall_printf("Looking for file %s\n", exename.c_str());

        demo->m_isoParser.getDirentry(exename, &entry, [coroutine, &success](bool s) {
            success = s;
            coroutine->resume();
        });
        co_await awaiter;
        if (!success) {
            demo->m_text = "CD-Rom failed reading, retrying...";
            ramsyscall_printf("Failed to read iso9660 structure to locate %s - damaged CD ?\n", exename.c_str());
            continue;
        }

        if (entry.type == psyqo::ISO9660Parser::DirEntry::FILE) {
            ramsyscall_printf("%s boot file found!\n", exename.c_str());
            demo->m_text = "Success!";
            co_return;
        }

        ramsyscall_printf("%s boot file not found... invalid CD-Rom?\n", exename.c_str());
        demo->m_text = "Invalid CD-Rom, retrying...";
    }
}

class CoroutineDemoScene final : public psyqo::Scene {
    void frame() override;
};

CoroutineDemo coroutineDemo;
CoroutineDemoScene coroutineDemoScene;

}  // namespace

void CoroutineDemo::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_cdrom.prepare();
}

void CoroutineDemo::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&coroutineDemoScene);
    m_coroutine = coroutine(this);
    m_coroutine.resume();
}

void CoroutineDemoScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    coroutineDemo.gpu().clear(bg);
    auto c = psyqo::Color{{.r = 255, .g = 255, .b = 255}};
    coroutineDemo.m_font.print(coroutineDemo.gpu(), coroutineDemo.m_text, {{.x = 4, .y = 32}}, c);

    if (coroutineDemo.m_coroutine.done()) {
        eastl::string_view systemcnf = {reinterpret_cast<const char *>(coroutineDemo.m_buffer),
                                        coroutineDemo.m_systemCnfSize};
        unsigned lineNumber = 0;
        if (systemcnf.empty()) {
            coroutineDemo.m_font.print(coroutineDemo.gpu(), "SYSTEM.CNF;1 file not found", {{.x = 4, .y = 64}}, c);
        } else {
            while (!systemcnf.empty()) {
                auto pos = systemcnf.find('\r');
                if (pos == eastl::string_view::npos) {
                    pos = systemcnf.length();
                }
                auto line = systemcnf.substr(0, pos);
                systemcnf.remove_prefix(pos + 1);
                if (systemcnf[0] == '\n') {
                    systemcnf.remove_prefix(1);
                }
                psyqo::Vertex v = {{.x = 4, .y = 64}};
                v.y += lineNumber * 16;
                lineNumber++;
                coroutineDemo.m_font.print(coroutineDemo.gpu(), line, v, c);
            }
        }
    }
}

int main() { return coroutineDemo.run(); }
