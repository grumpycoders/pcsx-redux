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

#ifdef __APPLE__
// Why has Apple become the Microsoft of Software Engineering?
#include <experimental/coroutine>
#else
#include <coroutine>
#endif
#include <type_traits>

namespace PCSX {

template <typename T = void>
struct Coroutine {
#ifdef __APPLE__
    template <typename U>
    using CoroutineHandle = std::experimental::coroutine_handle<U>;
    using CoroutineHandleVoid = std::experimental::coroutine_handle<void>;
#else
    template <typename U>
    using CoroutineHandle = std::coroutine_handle<U>;
    using CoroutineHandleVoid = std::coroutine_handle<void>;
#endif
    struct Empty {};
    typedef typename std::conditional<std::is_void<T>::value, Empty, T>::type SafeT;

    Coroutine() = default;
    Coroutine(Coroutine &&other) = default;
    Coroutine &operator=(Coroutine &&other) = default;
    Coroutine(Coroutine const &) = delete;
    Coroutine &operator=(Coroutine const &) = delete;

    struct Awaiter {
        constexpr bool await_ready() const noexcept { return false; }
        constexpr void await_suspend(CoroutineHandleVoid) const noexcept {}
        constexpr void await_resume() const noexcept {}
    };

    Awaiter awaiter() { return {}; }
    void resume() {
        if (!m_handle) return;
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
        Coroutine<T> get_return_object() { return Coroutine{std::move(CoroutineHandle<Promise>::from_promise(*this))}; }
        Awaiter initial_suspend() { return {}; }
        Awaiter final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        template <typename From>
        Awaiter yield_value(From &&from) {
            return {};
        }
        void return_void() {}
    };
    struct PromiseValue {
        PromiseValue(Coroutine<T> *c) : coroutine(c) {}
        Coroutine<T> get_return_object() { return Coroutine{std::move(CoroutineHandle<Promise>::from_promise(*this))}; }
        Awaiter initial_suspend() { return {}; }
        Awaiter final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        // This should be an std::convertible_to<T>, but Apple still doesn't have a fully C++-20 conformant library.
        template <typename From>
        Awaiter yield_value(From &&from) {
            coroutine->m_value = std::forward<From>(from);
            return {};
        }
        void return_value(T &&value) { coroutine->m_value = std::forward(value); }
        Coroutine<T> coroutine = nullptr;
    };
    typedef typename std::conditional<std::is_void<T>::value, PromiseVoid, PromiseValue>::type Promise;
    Coroutine(CoroutineHandle<Promise> &&handle) : m_handle(std::move(handle)) {}
    CoroutineHandle<Promise> m_handle;
    [[no_unique_address]] SafeT m_value;

  public:
    using promise_type = Promise;
};

}  // namespace PCSX
