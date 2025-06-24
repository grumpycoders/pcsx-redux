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

#include <EASTL/functional.h>
#include <EASTL/utility.h>

#include <coroutine>
#include <type_traits>

#include "common/psxlibc/ucontext.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/kernel.hh"

namespace psyqo {

/**
 * @brief A suitable type to hold and return a C++20 coroutine.
 *
 * @details C++20 introduced the concept of coroutines in the language. This
 * type can be used to properly hold a coroutine and yield and resume it
 * within psyqo. An important caveat of using coroutines is that the language
 * insists on calling `new` and `delete` silently within the coroutine object.
 * This may be a problem for users who don't want to use the heap.
 *
 * @tparam T The type the coroutine returns. `void` by default.
 */

template <typename T = void>
struct Coroutine {
    struct Empty {};
    typedef typename std::conditional<std::is_void<T>::value, Empty, T>::type SafeT;

    Coroutine() = default;

    Coroutine(Coroutine &&other) {
        if (m_handle) m_handle.destroy();
        m_handle = nullptr;
        m_handle = other.m_handle;
        m_value = eastl::move(other.m_value);
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
            m_handle = nullptr;
            m_handle = other.m_handle;
            m_value = eastl::move(other.m_value);
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

    /**
     * @brief The awaiter type.
     *
     * @details The awaiter type is the type that is used to suspend the coroutine
     * after scheduling an asynchronous operation. The keyword `co_await` can be used
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
        constexpr void await_suspend(std::coroutine_handle<> h) { m_coroutine->m_suspended = true; }
        constexpr void await_resume() const noexcept {}

      private:
        Awaiter(Coroutine *coroutine) : m_coroutine(coroutine) {}
        Coroutine *m_coroutine;
        friend struct Coroutine;
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
        void return_void() {
            if (m_awaitingCoroutine) {
                Kernel::queueCallback([h = m_awaitingCoroutine]() { h.resume(); });
                m_awaitingCoroutine = nullptr;
            }
        }
        [[no_unique_address]] Empty m_value;
        std::coroutine_handle<> m_awaitingCoroutine;
    };

    struct PromiseValue {
        Coroutine<T> get_return_object() {
            return Coroutine{eastl::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        void return_value(T &&value) {
            m_value = eastl::move(value);
            if (m_awaitingCoroutine) {
                Kernel::queueCallback([h = m_awaitingCoroutine]() { h.resume(); });
                m_awaitingCoroutine = nullptr;
            }
        }
        T m_value;
        std::coroutine_handle<> m_awaitingCoroutine;
    };

    typedef typename std::conditional<std::is_void<T>::value, PromiseVoid, PromiseValue>::type Promise;

    Coroutine(std::coroutine_handle<Promise> &&handle) : m_handle(eastl::move(handle)) {}

    std::coroutine_handle<Promise> m_handle;
    [[no_unique_address]] SafeT m_value;
    bool m_suspended = true;
    bool m_earlyResume = false;

  public:
    using promise_type = Promise;

    constexpr bool await_ready() { return m_handle.done(); }
    template <typename U>
    constexpr void await_suspend(std::coroutine_handle<U> h) {
        m_handle.promise().m_awaitingCoroutine = h;
        resume();
    }
    constexpr T await_resume() {
        if constexpr (std::is_void<T>::value) {
            return;
        } else {
            return eastl::move(m_handle.promise().m_value);
        }
    }
};

class StackfulBase {
  protected:
    void initializeInternal(eastl::function<void()> &&func, void *ss_sp, unsigned ss_size);
    void resume();
    void yield();
    [[nodiscard]] bool isAlive() const { return m_isAlive; }

    StackfulBase() = default;
    StackfulBase(const StackfulBase &) = delete;
    StackfulBase &operator=(const StackfulBase &) = delete;

  private:
    static void trampoline(void *arg) {
        StackfulBase *self = static_cast<StackfulBase *>(arg);
        self->trampoline();
    }
    void trampoline();
    ucontext_t m_coroutine;
    ucontext_t m_return;
    eastl::function<void()> m_func;
    bool m_isAlive = false;
};

/**
 * @brief Stackful coroutine class.
 *
 * @details This class provides a simple stackful coroutine implementation.
 * It allows you to create coroutines that can yield and resume execution.
 * While the Coroutine class above is a C++20 coroutine, it requires
 * that all of the code being run are coroutines or awaitables all the way down.
 * This class is a more traditional coroutine implementation that uses
 * a separate stack for each coroutine, allowing it to yield and resume
 * execution without requiring the entire call stack to be coroutine-aware.
 * It is suitable for use in scenarios where you need to yield execution
 * from legacy code without converting it to C++20 coroutines.
 */
template <unsigned StackSize = 0x10000>
class Stackful : public StackfulBase {
  public:
    static constexpr unsigned c_stackSize = (StackSize + 7) & ~7;

    Stackful() = default;
    Stackful(const Stackful &) = delete;
    Stackful &operator=(const Stackful &) = delete;

    /**
     * @brief Initialize the coroutine with a function and an argument.
     *
     * @param func Function to be executed by the coroutine.
     * @param arg Argument to be passed to the function.
     */
    void initialize(eastl::function<void()> &&func) {
        initializeInternal(eastl::move(func), m_stack.data, c_stackSize);
    }

    /**
     * @brief Resume the coroutine.
     *
     * @details This will switch to the coroutine's context and execute it.
     * If the coroutine is not alive, this function does nothing. This
     * function should be called after the coroutine has been initialized,
     * and it will return to the point where the coroutine was last yielded.
     * It can only be called from the "main thread".
     */
    void resume() { StackfulBase::resume(); }

    /**
     * @brief Yield the coroutine.
     *
     * @details This will switch back to the main thread and save the
     * coroutine's context. The coroutine can be resumed later using
     * `resume()`. It can only be called from within the coroutine
     * to yield execution.
     */
    void yield() { StackfulBase::yield(); }

    /**
     * @brief Check if the coroutine is currently alive.
     * @details A coroutine is considered alive if it has been initialized
     * and has not yet completed its execution. It becomes not alive
     * when it returns from its function.
     *
     * @return true if the coroutine is alive, false otherwise.
     */
    [[nodiscard]] bool isAlive() const { return StackfulBase::isAlive(); }

  private:
    struct alignas(8) Stack {
        uint8_t data[c_stackSize];
    };
    Stack m_stack;
};

}  // namespace psyqo
