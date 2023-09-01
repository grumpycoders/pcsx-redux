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

/**
 * @brief A suitable type to hold and return a C++20 coroutine.
 *
 * @details C++20 introduced the concept of coroutines in the language. This
 * type can be used to properly hold a coroutine and yield and resume it
 * within psyqo. An important caveat of using coroutines is that the language
 * insist on calling `new` and `delete` silently within the coroutine object.
 * This may be a problem for users who don't want to use the heap.
 *
 * @tparam T The type the coroutine returns. `void` by default.
 */

template <typename T = void>
struct Coroutine {
    struct Empty {};
    typedef typename std::conditional<std::is_void<T>::value, Empty, T>::type SafeT;

    Coroutine() = default;
    Coroutine(Coroutine &&other) = default;
    Coroutine &operator=(Coroutine &&other) = default;
    Coroutine(Coroutine const &) = delete;
    Coroutine &operator=(Coroutine const &) = delete;

    /**
     * @brief The awaiter type.
     *
     * @details The awaiter type is the type that is used to suspend the coroutine
     * after scheduling an asychronous operation. The keyword `co_await` can be used
     * on an instance of the object to suspend the current coroutine. Creating an
     * instance of this object is done by calling `coroutine.awaiter()`.
     */
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
        void await_suspend(std::coroutine_handle<> h) { m_coroutine->m_suspended = true; }
        constexpr void await_resume() const noexcept {}

      private:
        Awaiter(Coroutine *coroutine) : m_coroutine(coroutine) {}
        Coroutine *m_coroutine;
        friend class Coroutine;
    };

    /**
     * @brief Creates an `Awaiter` object.
     *
     * @details This method is used to create an instance of the `Awaiter` object.
     * It's used to suspend the coroutine after scheduling an asynchronous operation.
     */
    Awaiter awaiter() { return Awaiter(this); }

    /**
     * @brief Resumes the coroutine.
     *
     * @details This method resumes the coroutine. It's used to resume the coroutine
     * after an asynchronous operation has completed. It is safe to call it from
     * within the coroutine itself, meaning it is safe to call it from a callback
     * which may execute in the same callstack as the coroutine. In this case, the
     * next `co_yield` on the `Awaiter` object will be a no-op.
     */
    void resume() {
        if (!m_handle) return;
        if (!m_suspended) {
            m_earlyResume = true;
            return;
        }
        m_suspended = false;
        m_handle.resume();
    }

    /**
     * @brief Returns the status of the coroutine.
     *
     * @details This method returns the status of the coroutine. It will return
     * `true` if the coroutine is done executing, `false` otherwise. The typical
     * usage of this method is to poll it from the scene loop. The first time it
     * returns `true`, the coroutine will be destroyed. The next times, it will
     * return `true` without doing anything, making the polling loop faster.
     */
    bool done() {
        if (!m_handle) return true;
        bool isDone = m_handle.done();
        if (isDone) {
            if constexpr (!std::is_void<T>::value) {
                m_value = eastl::move(m_handle.promise().m_value);
            }
            m_handle.destroy();
            m_handle = nullptr;
        }
        return isDone;
    }

    /**
     * @brief Returns the value returned by the coroutine.
     *
     * @details This method returns the value returned by the coroutine. It is
     * only valid to call it after the coroutine has finished executing. The
     * typical usage of this method is to call it after the `done` method
     * returns `true`. The coroutine sets its return value using the `co_return`
     * keyword. Since it is possible for the return type to be `void`, the
     * return type of this method is `T` if `T` is not `void`, and `Empty` if
     * `T` is `void`.
     */
    const SafeT &value() const { return m_value; }

  private:
    struct PromiseVoid {
        Coroutine<> get_return_object() {
            return Coroutine<>{eastl::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        void return_void() {}
    };
    struct PromiseValue {
        Coroutine<T> get_return_object() {
            return Coroutine{eastl::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        void return_value(T &&value) { m_value = eastl::move(value); }
        T m_value;
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
