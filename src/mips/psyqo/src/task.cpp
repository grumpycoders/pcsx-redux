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

void psyqo::TaskQueue::reset() {
    m_queue.clear();
    m_catch = nullptr;
    m_finally = nullptr;
}

psyqo::TaskQueue& psyqo::TaskQueue::startWith(Task&& task) {
    reset();
    return then(eastl::move(task));
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
    m_parent = nullptr;
    m_index = 0;
    m_running = true;
    runNext();
}

psyqo::TaskQueue::Task psyqo::TaskQueue::schedule() {
    return Task([this](auto task) {
        m_parent = task;
        m_index = 0;
        m_running = true;
        runNext();
    });
}

void psyqo::TaskQueue::runNext() {
    if (m_index >= m_queue.size()) {
        m_running = false;
        if (m_finally) m_finally(this);
        if (m_parent) m_parent->resolve();
        return;
    }
    Task* task = &m_queue[m_index++];
    task->m_runner(task);
}

void psyqo::TaskQueue::runCatch() {
    m_running = false;
    if (m_catch && m_finally) {
        auto finally = eastl::move(m_finally);
        m_catch(this);
        finally(this);
    } else {
        if (m_catch) m_catch(this);
        if (m_finally) m_finally(this);
    }
    if (m_parent) m_parent->reject();
}
