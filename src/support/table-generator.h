/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include <type_traits>
#include <utility>

namespace PCSX {

namespace generator::details {

template <typename T, std::size_t N>
struct Table {
    const T data[N];
    T operator[](std::size_t index) const { return data[index]; }
    static constexpr std::size_t size() { return N; }
    const T* begin() const { return &data[0]; }
    const T* end() const { return &data[N]; }
};

template <typename A>
consteval A& makeRef() {
    A a;
    return a;
}

template <typename T, std::size_t N, typename Generator, std::size_t... Is>
consteval Table<T, N> generateTable(std::index_sequence<Is...>) {
    return {{Generator::calculateValue(Is)...}};
}

template <typename T, std::size_t N, typename Generator, typename A, std::size_t... Is>
consteval Table<T, N> generateTable(A acc, std::index_sequence<Is...>) {
    return {{Generator::calculateValue(Is, acc)...}};
}

}  // namespace generator::details

template <std::size_t N, typename Generator>
consteval generator::details::Table<decltype(Generator::calculateValue(0)), N> generateTable() {
    return generator::details::generateTable<decltype(Generator::calculateValue(0)), N, Generator>(
        std::make_index_sequence<N>{});
}

template <std::size_t N, typename Generator, typename A>
consteval generator::details::Table<decltype(Generator::calculateValue(0, generator::details::makeRef<A>())), N>
generateTable(A acc) {
    return generator::details::generateTable<decltype(Generator::calculateValue(0, generator::details::makeRef<A>())),
                                             N, Generator, A>(acc, std::make_index_sequence<N>{});
}

}  // namespace PCSX
