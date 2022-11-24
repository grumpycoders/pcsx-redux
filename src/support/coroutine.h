/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once

#include <coroutine>
#include <type_traits>

namespace PCSX {

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
        Awaiter(Awaiter &&other) = default;
        Awaiter &operator=(Awaiter &&other) = default;
        Awaiter(Awaiter const &) = default;
        Awaiter &operator=(Awaiter const &) = default;
        constexpr bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> h) {}
        constexpr void await_resume() const noexcept {}

      private:
        Awaiter(Coroutine *coroutine) : m_coroutine(coroutine) {}
        Coroutine *m_coroutine;
        friend struct Coroutine;
    };

    Awaiter awaiter() { return Awaiter(this); }
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
        Coroutine<T> get_return_object() {
            return Coroutine{std::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        template <typename From>
        std::suspend_always yield_value(From &&from) {
            return {};
        }
        void return_void() {}
    };
    struct PromiseValue {
        PromiseValue(Coroutine<T> *c) : coroutine(c) {}
        Coroutine<T> get_return_object() {
            return Coroutine{std::move(std::coroutine_handle<Promise>::from_promise(*this))};
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() {}
        template <std::convertible_to<T> From>
        std::suspend_always yield_value(From &&from) {
            coroutine->m_value = std::forward<From>(from);
            return {};
        }
        void return_value(T &&value) { coroutine->m_value = std::forward(value); }
        Coroutine<T> coroutine = nullptr;
    };
    typedef typename std::conditional<std::is_void<T>::value, PromiseVoid, PromiseValue>::type Promise;
    Coroutine(std::coroutine_handle<Promise> &&handle) : m_handle(std::move(handle)) {}
    std::coroutine_handle<Promise> m_handle;
    [[no_unique_address]] SafeT m_value;

  public:
    using promise_type = Promise;
};

}  // namespace PCSX
