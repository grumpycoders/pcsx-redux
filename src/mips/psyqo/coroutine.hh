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

#pragma once

#include <coroutine>
#include <type_traits>

namespace psyqo {

template <typename T = void>
struct Coroutine {
    struct Empty {};
    typedef typename std::conditional<std::is_void<T>::value, Empty, T>::type SafeT;

    Coroutine() = default;
    Coroutine(Coroutine &&other) = default;
    Coroutine &operator=(Coroutine &&other) = default;
    Coroutine(Coroutine const &) = delete;
    Coroutine &operator=(Coroutine const &) = delete;

    struct Awaiter {
        Coroutine *coroutine;
        constexpr bool await_ready() const noexcept {
            bool ret = coroutine->m_earlyResume;
            coroutine->m_earlyResume = false;
            return ret;
        }
        void await_suspend(std::coroutine_handle<> h) { coroutine->m_suspended = true; }
        constexpr void await_resume() const noexcept {}
    };

    void resume() {
        if (!m_handle) return;
        if (!m_suspended) {
            m_earlyResume = true;
            return;
        }
        m_suspended = false;
        m_handle.resume();
    }

    bool done() {
        if (!m_handle) return true;
        bool isDone = m_handle.done();
        if (isDone) {
            m_handle.destroy();
            m_handle = nullptr;
        }
        return isDone;
    }

    const SafeT &value() const { return m_value; }

  private:
    struct PromiseVoid {
        Coroutine get_return_object() {
            return Coroutine{eastl::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        void return_void() {}
    };
    struct PromiseValue {
        PromiseValue(Coroutine<T> *c) : coroutine(c) {}
        Coroutine<T> get_return_object() {
            return Coroutine{eastl::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        void return_value(T &&value) { coroutine->m_value = eastl::move(value); }
        Coroutine<T> coroutine = nullptr;
    };
    typedef typename std::conditional<std::is_void<T>::value, PromiseVoid, PromiseValue>::type Promise;
    Coroutine(std::coroutine_handle<Promise> &&handle) : m_handle(eastl::move(handle)) {}
    std::coroutine_handle<Promise> m_handle;
    [[no_unique_address]] SafeT m_value;
    bool m_suspended = true;
    bool m_earlyResume = false;

  public:
    using promise_type = Promise;
};

}  // namespace psyqo
