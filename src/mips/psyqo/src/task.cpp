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

#include "psyqo/task.hh"

psyqo::TaskQueue& psyqo::TaskQueue::start(Task&& task) {
    task.m_taskQueue = this;
    m_queue.clear();
    m_catch = nullptr;
    m_finally = nullptr;
    m_queue.push_back(eastl::move(task));
    run();

    return *this;
}

psyqo::TaskQueue& psyqo::TaskQueue::then(Task&& task) {
    task.m_taskQueue = this;
    m_queue.push_back(eastl::move(task));

    return *this;
}

psyqo::TaskQueue& psyqo::TaskQueue::butCatch(eastl::function<void(TaskQueue*)>&& fun) {
    m_catch = eastl::move(fun);

    return *this;
}

psyqo::TaskQueue& psyqo::TaskQueue::finally(eastl::function<void(TaskQueue*)>&& fun) {
    m_finally = eastl::move(fun);

    return *this;
}

void psyqo::TaskQueue::run() {
    m_index = 0;
    runNext();
}

void psyqo::TaskQueue::runNext() {
    if (m_index >= m_queue.size()) {
        if (m_finally) m_finally(this);
        return;
    }
    Task* task = &m_queue[m_index++];
    task->m_runner(task);
}

void psyqo::TaskQueue::runCatch() {
    if (m_catch) m_catch(this);
    if (m_finally) m_finally(this);
}
