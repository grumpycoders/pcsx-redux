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

#include "psyqo/coroutine.hh"

void psyqo::StackfulBase::initializeInternal(eastl::function<void()>&& func, void* ss_sp, unsigned ss_size) {
    m_isAlive = true;
    m_func = eastl::move(func);
    getcontext(&m_coroutine);
    m_coroutine.uc_stack.ss_sp = ss_sp;
    m_coroutine.uc_stack.ss_size = ss_size;
    m_coroutine.uc_link = &m_return;
    makecontext(&m_coroutine, trampoline, this);
}

void psyqo::StackfulBase::trampoline() {
    m_func();
    m_isAlive = false;
}

void psyqo::StackfulBase::resume() {
    if (!m_isAlive) return;
    swapcontext(&m_return, &m_coroutine);
}

void psyqo::StackfulBase::yield() {
    if (!m_isAlive) return;
    swapcontext(&m_coroutine, &m_return);
}
