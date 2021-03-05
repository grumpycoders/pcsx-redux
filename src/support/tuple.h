/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <stdint.h>

#include <type_traits>

namespace PCSX {

// This implementation of tuple is to make clang-cl happy, since it cannot work the
// implementation from Microsoft's STL:
// https://developercommunity2.visualstudio.com/t/microsoft-stls-tuple-incompatible-with-clang-cl/1353663
// It's a simplified version of the normal tuple container, and hopefully will
// work well within the parameters of what we need it to. Its implementation is
// inspired from various actual implementations of std::tuple.

namespace SimpleTupleImpl {

template <size_t... indices>
struct IndexSequence {
    using type = IndexSequence<indices...>;
};
template <size_t index, typename sequence>
struct CatIndexSequence;
template <size_t index, size_t... indices>
struct CatIndexSequence<index, IndexSequence<indices...>> : IndexSequence<indices..., index> {};
template <size_t N>
struct MakeIndexSequence : CatIndexSequence<N - 1, typename MakeIndexSequence<N - 1>::type>::type {};
template <>
struct MakeIndexSequence<1> : IndexSequence<0> {};

template <size_t index, typename type>
struct SimpleTupleElement {
    type value;
};

template <typename... Types>
struct TupleTypes {};

template <typename>
static constexpr int findInner(int) {
    return -1;
}
template <typename type, typename head, typename... tail>
static constexpr int findInner(int index = 0) {
    return std::is_same<type, head>::value ? index : findInner<type, tail...>(index + 1);
}

template <size_t index, typename... Types>
struct TypeAtIndex;

template <typename head, typename... Types>
struct TypeAtIndex<0, TupleTypes<head, Types...>> {
    using type = head;
};

template <size_t index, typename head, typename... Types>
struct TypeAtIndex<index, TupleTypes<head, Types...>> {
    using type = typename TypeAtIndex<index - 1, TupleTypes<Types...>>::type;
};

template <typename type, typename... Types>
constexpr int find() {
    return findInner<type, Types...>();
}

template <typename sequences, typename... Types>
struct SimpleTupleImpl;

template <size_t... indices, typename... Types>
struct SimpleTupleImpl<IndexSequence<indices...>, Types...> : SimpleTupleElement<indices, Types>... {};

template <size_t index, typename... Types>
constexpr typename TypeAtIndex<index, TupleTypes<Types...>>::type& getAt(
    SimpleTupleImpl<typename MakeIndexSequence<sizeof...(Types)>::type, Types...>* tuple) {
    return static_cast<SimpleTupleElement<index, typename TypeAtIndex<index, TupleTypes<Types...>>::type>*>(tuple)
        ->value;
}

template <size_t index, typename... Types>
constexpr const typename TypeAtIndex<index, TupleTypes<Types...>>::type& getAt(
    const SimpleTupleImpl<typename MakeIndexSequence<sizeof...(Types)>::type, Types...>* tuple) {
    return static_cast<const SimpleTupleElement<index, typename TypeAtIndex<index, TupleTypes<Types...>>::type>*>(tuple)
        ->value;
}

}  // namespace SimpleTupleImpl

template <typename... Types>
struct SimpleTuple
    : SimpleTupleImpl::SimpleTupleImpl<typename SimpleTupleImpl::MakeIndexSequence<sizeof...(Types)>::type, Types...> {
};

}  // namespace PCSX
