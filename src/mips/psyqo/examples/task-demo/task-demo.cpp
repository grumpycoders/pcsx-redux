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
#include "psyqo/font.hh"
#include "psyqo/gpu.hh"
#include "psyqo/iso9660-parser.hh"
#include "psyqo/scene.hh"
#include "psyqo/task.hh"
#include "psyqo/xprintf.h"

namespace {

class TaskDemo final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
    psyqo::CDRomDevice m_cdrom;
    psyqo::ISO9660Parser m_isoParser = psyqo::ISO9660Parser(&m_cdrom);
    psyqo::ISO9660Parser::ReadRequest m_request;
    psyqo::TaskQueue m_queue;
    eastl::fixed_string<char, 256> m_text;
    uint8_t m_buffer[2048];
    uint32_t m_systemCnfSize;
    bool m_done = false;
};

class TaskDemoScene final : public psyqo::Scene {
    void frame() override;
};

TaskDemo taskDemo;
TaskDemoScene taskDemoScene;

}  // namespace

void TaskDemo::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
    m_cdrom.prepare();
}

void TaskDemo::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&taskDemoScene);
    m_queue
        .startWith([this](auto task) {
            m_text = "Initializing CDROM...";
            syscall_puts("Initializing CDROM...\n");
            task->resolve();
        })
        .then(m_cdrom.scheduleReset())
        .then(m_isoParser.scheduleInitialize())
        .then([this](auto task) {
            m_text = "Finding SYSTEM.CNF;1...";
            syscall_puts("Finding SYSTEM.CNF;1...\n");
            task->resolve();
        })
        .then(m_isoParser.scheduleGetDirentry("SYSTEM.CNF;1", &m_request.entry))
        .then([this](auto task) {
            if (m_request.entry.type == psyqo::ISO9660Parser::DirEntry::INVALID) {
                m_text = "SYSTEM.CNF;1 not found!";
                syscall_puts("SYSTEM.CNF;1 not found!\n");
                task->reject();
                return;
            }
            if (m_request.entry.size > 2048) {
                m_text = "SYSTEM.CNF;1 too big!";
                syscall_puts("SYSTEM.CNF;1 too big!\n");
                task->reject();
                return;
            }
            m_request.buffer = m_buffer;
            m_text = "Reading SYSTEM.CNF;1...";
            syscall_puts("Reading SYSTEM.CNF;1...\n");
            task->resolve();
        })
        .then(m_isoParser.scheduleReadRequest(&m_request))
        .then([this](auto task) {
            m_text = "Success!";
            syscall_puts("Success!\n");
            m_systemCnfSize = m_request.entry.size;
            m_done = true;
            task->resolve();
        })
        .butCatch([this](auto queue) {
            m_text = "Failure, retrying...";
            syscall_puts("Failure, retrying...\n");
            using namespace psyqo::timer_literals;
            gpu().armTimer(gpu().now() + 1_s, [queue](auto) { queue->run(); });
        })
        .run();
}

void TaskDemoScene::frame() {
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    taskDemo.gpu().clear(bg);
    taskDemo.m_font.print(taskDemo.gpu(), taskDemo.m_text, {{.x = 4, .y = 32}}, {.r = 255, .g = 255, .b = 255});

    if (taskDemo.m_done) {
        eastl::string_view systemcnf = {reinterpret_cast<const char *>(taskDemo.m_buffer), taskDemo.m_systemCnfSize};
        unsigned lineNumber = 0;
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
            taskDemo.m_font.print(taskDemo.gpu(), line, v, {.r = 255, .g = 255, .b = 255});
        }
    }
}

int main() { return taskDemo.run(); }
