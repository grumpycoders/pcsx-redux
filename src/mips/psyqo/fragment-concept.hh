/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include <stddef.h>

#include <concepts>
#include <type_traits>

namespace psyqo {

template <typename T, class Enable = void>
struct has_explicit_copy_constructor : std::false_type {};

template <typename T>
struct has_explicit_copy_constructor<
    T, typename std::enable_if<std::is_copy_constructible_v<T> && !std::is_convertible_v<const T&, T>>::type>
    : std::true_type {};

/**
 * @brief The Fragment concept.
 * @details This concept can be used as a template type constraint
 * to ensure that a type is a valid fragment.
 */

template <typename Frag>
concept Fragment = requires(Frag frag) {
    { (alignof(Frag) & 3) == 0 };
    { (sizeof(Frag) & 3) == 0 };
    { (sizeof(frag.head)) == 4 };
    { ((offsetof(Frag, head)) & 3) == 0 };
    // Can't seem to make this work with variadic templated constructors
    // { has_explicit_copy_constructor<Frag>() } -> std::convertible_to<std::true_type>;
    { frag.getActualFragmentSize() } -> std::convertible_to<size_t>;
};

}  // namespace psyqo
