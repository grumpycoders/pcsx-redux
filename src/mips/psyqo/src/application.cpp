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

#include "psyqo/application.hh"

#include <utility>

#include "common/syscalls/syscalls.h"
#include "psyqo/alloc.h"
#include "psyqo/gte-registers.hh"
#include "psyqo/kernel.hh"
#include "psyqo/scene.hh"

template <unsigned... regs>
static inline void clearAllGTERegistersInternal(std::integer_sequence<unsigned, regs...> regSeq) {
    ((psyqo::GTE::clear<static_cast<psyqo::GTE::Register>(regs), psyqo::GTE::Unsafe>)(), ...);
}

static inline void clearAllGTERegisters() { clearAllGTERegistersInternal(std::make_integer_sequence<unsigned, 64>{}); }

int psyqo::Application::run() {
    Kernel::fastEnterCriticalSection();
    Kernel::Internal::prepare(*this);
    syscall_puts("*** PSYQo Application - starting ***\n");
    psyqo_free(psyqo_malloc(1));
    ramsyscall_printf("Current heap start: %p\n", psyqo_heap_start());
    ramsyscall_printf("Current heap end: %p\n", psyqo_heap_end());
    clearAllGTERegisters();
    prepare();
    Kernel::fastLeaveCriticalSection();
    start();
    while (true) {
        frame();
        m_gpu.flip();
    }
    __builtin_unreachable();
}

void psyqo::Application::frame() {
    if (m_scenesStack.empty()) {
        createScene();
    }
    Kernel::assert(m_scenesStack.size() > 0, "Scenes stack is empty");
    getCurrentScene()->frame();
}

psyqo::Scene* psyqo::Application::getCurrentScene() {
    if (m_scenesStack.empty()) {
        return nullptr;
    }
    return m_scenesStack.back();
}

void psyqo::Application::pushScene(Scene* scene) {
    if (m_scenesStack.size() > 0) {
        m_scenesStack.back()->teardown(Scene::TearDownReason::Pause);
    }
    m_scenesStack.push_back(scene);
    scene->m_parent = this;
    scene->start(Scene::StartReason::Create);
}

psyqo::Scene* psyqo::Application::popScene() {
    if (m_scenesStack.empty()) {
        return nullptr;
    }
    Scene* top = m_scenesStack.back();
    top->teardown(Scene::TearDownReason::Destroy);
    m_scenesStack.pop_back();
    if (m_scenesStack.size() > 0) {
        m_scenesStack.back()->start(Scene::StartReason::Resume);
    }
    return top;
}
