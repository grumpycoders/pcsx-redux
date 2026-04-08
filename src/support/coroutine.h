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
#include <utility>

namespace PCSX {

template <typename T = void>
struct Coroutine {
    struct Empty {};
    typedef typename std::conditional<std::is_void<T>::value, Empty, T>::type SafeT;

    Coroutine() = default;

    Coroutine(Coroutine &&other) {
        if (m_handle) m_handle.destroy();
        m_handle = other.m_handle;
        m_value = std::move(other.m_value);
        m_suspended = other.m_suspended;
        m_earlyResume = other.m_earlyResume;

        other.m_handle = nullptr;
        other.m_value = SafeT{};
        other.m_suspended = true;
        other.m_earlyResume = false;
    }

    Coroutine &operator=(Coroutine &&other) {
        if (this != &other) {
            if (m_handle) m_handle.destroy();
            m_handle = other.m_handle;
            m_value = std::move(other.m_value);
            m_suspended = other.m_suspended;
            m_earlyResume = other.m_earlyResume;

            other.m_handle = nullptr;
            other.m_value = SafeT{};
            other.m_suspended = true;
            other.m_earlyResume = false;
        }
        return *this;
    }

    Coroutine(Coroutine const &) = delete;
    Coroutine &operator=(Coroutine const &) = delete;
    ~Coroutine() {
        if (m_handle) m_handle.destroy();
        m_handle = nullptr;
    }

    struct Awaiter {
        Awaiter(Awaiter &&other) = default;
        Awaiter &operator=(Awaiter &&other) = default;
        Awaiter(Awaiter const &) = default;
        Awaiter &operator=(Awaiter const &) = default;
        constexpr bool await_ready() const noexcept {
            bool ret = m_coroutine->m_earlyResume;
            m_coroutine->m_earlyResume = false;
            return ret;
        }
        constexpr void await_suspend(std::coroutine_handle<> h) { m_coroutine->m_suspended = true; }
        constexpr void await_resume() const noexcept {}

      private:
        Awaiter(Coroutine *coroutine) : m_coroutine(coroutine) {}
        Coroutine *m_coroutine;
        friend struct Coroutine;
    };

    Awaiter awaiter() { return Awaiter(this); }

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
            if constexpr (!std::is_void<T>::value) {
                m_value = std::move(m_handle.promise().m_value);
            }
            m_handle.destroy();
            m_handle = nullptr;
        }
        return isDone;
    }

    const SafeT &value() const { return m_value; }

  private:
    struct PromiseVoid {
        Coroutine<> get_return_object() {
            return Coroutine<>{std::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        template <typename From>
        From yield_value(From &&from) {
            return std::forward<From>(from);
        }
        void return_void() {
            if (m_awaitingCoroutine) {
                m_awaitingCoroutine.resume();
                m_awaitingCoroutine = nullptr;
            }
        }
        [[no_unique_address]] Empty m_value;
        std::coroutine_handle<> m_awaitingCoroutine;
    };

    struct PromiseValue {
        Coroutine<T> get_return_object() {
            return Coroutine{std::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        template <typename From>
        From yield_value(From &&from) {
            return std::forward<From>(from);
        }
        void return_value(T &&value) {
            m_value = std::move(value);
            if (m_awaitingCoroutine) {
                m_awaitingCoroutine.resume();
                m_awaitingCoroutine = nullptr;
            }
        }
        T m_value;
        std::coroutine_handle<> m_awaitingCoroutine;
    };

    typedef typename std::conditional<std::is_void<T>::value, PromiseVoid, PromiseValue>::type Promise;

    Coroutine(std::coroutine_handle<Promise> &&handle) : m_handle(std::move(handle)) {}

    std::coroutine_handle<Promise> m_handle;
    [[no_unique_address]] SafeT m_value;
    bool m_suspended = true;
    bool m_earlyResume = false;

  public:
    using promise_type = Promise;

    struct ChainAwaiter {
        std::coroutine_handle<Promise> handle;

        explicit ChainAwaiter(std::coroutine_handle<Promise> h) : handle(h) {}
        ~ChainAwaiter() {
            if (handle) handle.destroy();
        }

        ChainAwaiter(ChainAwaiter &&other) : handle(other.handle) { other.handle = nullptr; }
        ChainAwaiter &operator=(ChainAwaiter &&) = delete;
        ChainAwaiter(const ChainAwaiter &) = delete;
        ChainAwaiter &operator=(const ChainAwaiter &) = delete;

        constexpr bool await_ready() { return handle.done(); }

        void await_suspend(std::coroutine_handle<> h) {
            handle.promise().m_awaitingCoroutine = h;
            if (!handle.done()) handle.resume();
        }

        constexpr T await_resume() {
            if constexpr (std::is_void<T>::value) {
                handle.destroy();
                handle = nullptr;
                return;
            } else {
                auto val = std::move(handle.promise().m_value);
                handle.destroy();
                handle = nullptr;
                return val;
            }
        }
    };

    ChainAwaiter operator co_await() && {
        auto h = m_handle;
        m_handle = nullptr;
        return ChainAwaiter{h};
    }
};

}  // namespace PCSX
