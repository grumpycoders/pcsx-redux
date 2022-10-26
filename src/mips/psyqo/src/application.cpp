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

#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/alloc.h"
#include "psyqo/kernel.hh"
#include "psyqo/scene.hh"

int psyqo::Application::run() {
    enterCriticalSection();
    syscall_puts("*** PSYQo Application - starting ***\n");
    ramsyscall_printf("Current heap start: %p\n", psyqo_heap_start());
    ramsyscall_printf("Current heap end: %p\n", psyqo_heap_end());
    Kernel::Internal::prepare();
    prepare();
    leaveCriticalSection();
    while (true) {
        if (m_scenesStack.empty()) {
            createScene();
        }
        Kernel::assert(m_scenesStack.size() > 0, "Scenes stack is empty");
        getCurrentScene()->frame();
        m_gpu.flip();
    }

    return 0;
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
