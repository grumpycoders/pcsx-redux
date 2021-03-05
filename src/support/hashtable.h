/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <functional>
#include <iterator>
#include <type_traits>
#include <vector>

namespace PCSX {

namespace Intrusive {

struct DefaultHashTable {};

template <typename Key>
struct Hash {
    static constexpr uint32_t hash(const Key& key) { return static_cast<uint32_t>(std::hash<Key>{}(key)); }
    static constexpr bool isEqual(const Key& lhs, const Key& rhs) { return std::equal_to<Key>{}(lhs, rhs); }
};

template <typename Key, class T, class Hash = Hash<Key>, class Id = DefaultHashTable>
class HashTable final {
  public:
    class Node {
      public:
        Node() {}
        Node(const Node&) = delete;
        Node& operator=(const Node&) = delete;
        Node(Node&& src) = delete;
        ~Node() { unlink(); }
        bool isLinked() const { return m_parent; }
        void unlink() {
            if (!isLinked()) return;
            m_parent->unlink(this);
        }
        const Key& getKey() { return m_key; }

      private:
        void unlinkInternal() { m_parent = nullptr; }
        friend class HashTable;
        Key m_key = Key();
        Node* m_next = nullptr;
        HashTable<Key, T, Hash, Id>* m_parent = nullptr;
        uint32_t m_hash = 0;
    };

  private:
    template <class Derived, class Base>
    class IteratorBase final {
      public:
        typedef std::forward_iterator_tag iterator_category;
        typedef Derived value_type;
        typedef ptrdiff_t difference_type;
        typedef Derived* pointer;
        typedef Derived& reference;

        IteratorBase(Base* node = nullptr) : m_node(node) { static_assert(std::is_base_of<Base, Derived>::value); }
        template <class srcDerived, class srcBase>
        IteratorBase(const IteratorBase<srcDerived, srcBase>& src) : m_node(src.m_node) {}
        template <class srcDerived, class srcBase>
        IteratorBase& operator=(IteratorBase<srcDerived, srcBase> const& src) {
            m_node = src.m_node;
            return *this;
        }
        template <class srcDerived, class srcBase>
        bool operator==(const IteratorBase<srcDerived, srcBase>& src) const {
            return m_node == src.m_node;
        }
        template <class srcDerived, class srcBase>
        bool operator!=(const IteratorBase<srcDerived, srcBase>& src) const {
            return m_node != src.m_node;
        }
        Derived& operator*() const { return *static_cast<Derived*>(m_node); }
        Derived* operator->() const { return static_cast<Derived*>(m_node); }
        IteratorBase& operator++() {
            next();
            return *this;
        }
        IteratorBase operator++(int) {
            IteratorBase copy(*this);
            next();
            return copy;
        }

      private:
        void next() {
            Node* node = m_node;
            auto parent = node->m_parent;
            uint32_t hash = node->m_hash;
            node = m_node = node->m_next;
            if (!node && parent) m_node = parent->findNext(hash);
        }
        friend class HashTable;

        Base* m_node = nullptr;
    };

  public:
    typedef IteratorBase<T, Node> iterator;
    typedef IteratorBase<const T, const Node> const_iterator;

    friend class IteratorBase<T, Node>;
    friend class IteratorBase<const T, const Node>;

    HashTable(unsigned initLog = 1) {
        m_array.resize(1ULL << initLog);
        m_mask = (1U << initLog) - 1;
        m_bits = initLog;
    }

    unsigned size() { return m_count; }
    iterator begin() { return iterator(findFirst()); }
    const_iterator begin() const { return const_iterator(findFirst()); }
    const_iterator cbegin() const { return const_iterator(findFirst()); }
    iterator end() { return iterator(nullptr); }
    const_iterator end() const { return const_iterator(nullptr); }
    const_iterator cend() const { return const_iterator(nullptr); }
    bool empty() const { return m_count == 0; }
    void clear() {
        for (auto& i : m_array) {
            for (Node* p = i; p; p = p->m_next) p->m_parent = nullptr;
        }
        m_count = 0;
    }
    iterator insert(const Key& key, Node* node) {
        node->unlink();
        maybeGrow();

        node->m_key = key;
        uint32_t bucket = (node->m_hash = Hash::hash(key)) & m_mask;

        for (Node* p = m_array[bucket]; p; p = p->m_next) {
            if (Hash::isEqual(key, p->m_key)) {
                p->unlink();
                break;
            }
        }

        node->m_next = m_array[bucket];
        m_array[bucket] = node;
        node->m_parent = this;

        m_count++;
        return iterator(node);
    }
    iterator find(const Key& key) {
        uint32_t bucket = Hash::hash(key) & m_mask;
        for (Node* p = m_array[bucket]; p; p = p->m_next) {
            if (Hash::isEqual(key, p->m_key)) {
                return iterator(p);
            }
        }
        return end();
    }
    iterator erase(iterator i) {
        Node* node = i.m_node;
        i++;
        unlink(node);
        return i;
    }
    iterator buildIterator(Node* node) const {
        if (!isLinked(node)) return end();
        return iterator(node);
    }
    const_iterator buildConstIterator(Node* node) const {
        if (!isLinked(node)) return end();
        return const_iterator(node);
    }
    void unlink(Node* node) {
        if (node->m_parent != this) return;
        uint32_t bucket = node->m_hash & m_mask;
        Node* p = m_array[bucket];
        if (node == p) {
            m_array[bucket] = node->m_next;
        } else {
            while (true) {
                if (p->m_next == node) {
                    p->m_next = node->m_next;
                    break;
                }
                p = p->m_next;
            }
        }
        node->unlinkInternal();
        m_count--;
    }
    bool contains(Node* node) { return this == node->m_parent; }
    void destroyAll() {
        for (auto& i : m_array) destroyAll(i);
        auto oldSize = m_array.size();
        m_array.clear();
        m_array.resize(oldSize);
        m_count = 0;
    }

  private:
    void maybeGrow() {
        if ((1U << m_bits) > m_count) return;
        std::vector<Node*> newArray;
        m_bits++;
        const uint32_t mask = m_mask = (1U << m_bits) - 1;
        newArray.resize(mask + 1);

        for (auto& i : m_array) {
            for (Node* p = i; p;) {
                Node* node = p;
                p = node->m_next;
                uint32_t bucket = node->m_hash & mask;
                node->m_next = newArray[bucket];
                newArray[bucket] = node;
            }
        }

        m_array = std::move(newArray);
    }
    Node* findFirst() {
        for (auto& i : m_array) {
            if (i) return i;
        }
        return nullptr;
    }
    Node* findNext(uint32_t hash) {
        unsigned bucket = hash & m_mask;
        for (bucket++; bucket < m_array.size(); bucket++) {
            if (m_array[bucket]) return m_array[bucket];
        }
        return nullptr;
    }
    void destroyAll(Node* node) {
        if (!node) return;
        Node* next = node->m_next;
        node->m_parent = nullptr;
        delete node;
        destroyAll(next);
    }
    std::vector<Node*> m_array;
    unsigned m_count = 0;
    unsigned m_bits = 0;
    uint32_t m_mask = 0;
};

}  // namespace Intrusive

}  // namespace PCSX
