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

#include <iterator>
#include <type_traits>

namespace PCSX {

namespace Intrusive {

struct DefaultList {};

template <class T, class Id = DefaultList>
class List final {
  public:
    class Node {
      public:
        Node() {}
        Node(const Node&) {}
        Node& operator=(const Node&) { unlink(); }
        Node(Node&& src) {
            m_prev = src.m_prev;
            m_next = src.m_next;
            m_parent = src.m_parent;

            m_next->m_prev = m_prev->m_next = this;

            src.m_parent = nullptr;
        }
        virtual ~Node() { unlink(); }
        bool isLinked() const { return m_parent; }
        void unlink() {
            if (!isLinked()) return;
            m_parent->unlink(this);
        }

      private:
        void unlinkInternal() {
            m_next->m_prev = m_prev;
            m_prev->m_next = m_next;
            m_parent = nullptr;
        }
        friend class List;
        Node *m_prev = nullptr, *m_next = nullptr;
        List<T, Id>* m_parent = nullptr;
    };

  private:
    template <class Derived, class Base>
    class IteratorBase final {
      public:
        typedef std::bidirectional_iterator_tag iterator_category;
        typedef Derived value_type;
        typedef ptrdiff_t difference_type;
        typedef Derived* pointer;
        typedef Derived& reference;

        IteratorBase(Base* node = nullptr) : m_node(node) { static_assert(std::is_base_of<Base, Derived>::value); }
        template <class srcDerived, class srcBase>
        IteratorBase(const IteratorBase<srcDerived, srcBase>& src) : m_node(src.m_node) {}
        template <class srcDerived, class srcBase>
        IteratorBase& operator=(const IteratorBase<srcDerived, srcBase>& src) {
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
            m_node = m_node->m_next;
            return *this;
        }
        IteratorBase operator++(int) {
            IteratorBase copy(*this);
            m_node = m_node->m_next;
            return copy;
        }
        IteratorBase& operator--() {
            m_node = m_node->m_prev;
            return *this;
        }
        IteratorBase operator--(int) {
            IteratorBase copy(*this);
            m_node = m_node->m_prev;
            return copy;
        }

      private:
        friend class List;

        Base* m_node = nullptr;
    };

  public:
    typedef IteratorBase<T, Node> iterator;
    typedef IteratorBase<const T, const Node> const_iterator;

    List() {
        m_head.m_prev = nullptr;
        m_tail.m_next = nullptr;
        m_head.m_next = &m_tail;
        m_tail.m_prev = &m_head;
    }

    unsigned size() const { return m_count; }
    iterator begin() { return iterator(m_head.m_next); }
    const_iterator begin() const { return const_iterator(m_head.m_next); }
    const_iterator cbegin() const { return const_iterator(m_head.m_next); }
    iterator end() { return iterator(&m_tail); }
    const_iterator end() const { return const_iterator(&m_tail); }
    const_iterator cend() const { return const_iterator(&m_tail); }
    bool empty() const { return m_count == 0; }
    void clear() {
        for (Node* ptr = m_head.m_next; ptr; ptr = ptr->m_next) ptr->m_parent = nullptr;
        m_head.m_next = m_tail.m_prev = nullptr;
        m_count = 0;
    }
    iterator insert(iterator i, Node* node) {
        node->unlink();
        node->m_next = i.m_node;
        node->m_prev = i.m_node->m_prev;
        node->m_parent = this;
        node->m_next->m_prev = node;
        node->m_prev->m_next = node;
        m_count++;
        return iterator(node);
    }
    void merge(iterator i, List& list) {
        while (!list.empty()) insert(i, &*list.begin());
    }
    iterator erase(iterator i) {
        Node* node = i.m_node;
        i++;
        unlink(node);
        return i;
    }
    void push_front(Node* node) { insert(begin(), node); }
    void pop_front() {
        if (empty()) return;
        erase(begin());
    }
    void push_back(Node* node) { insert(end(), node); }
    void pop_back() {
        if (empty()) return;
        erase(--end());
    }
    void prepend(List& list) { merge(begin(), list); }
    void append(List& list) { merge(end(), list); }
    void swap(List& list) {
        unsigned localCount = size();
        unsigned remoteCount = list.size();
        for (unsigned i = 0; i < localCount; i++) {
            list.push_back(&*begin());
        }
        for (unsigned i = 0; i < remoteCount; i++) {
            push_back(&*list.begin());
        }
    }
    iterator buildIterator(Node* node) const {
        if (!isLinked(node)) return end();
        return iterator(node);
    }
    const_iterator buildConstIterator(Node* node) const {
        if (!contains(node)) return end();
        return const_iterator(node);
    }
    void unlink(Node* node) {
        if (node->m_parent != this) return;
        node->unlinkInternal();
        m_count--;
    }
    bool contains(Node* node) const { return this == node->m_parent; }
    void destroyAll() {
        while (m_count) delete m_head.m_next;
    }

  private:
    unsigned m_count = 0;
    Node m_tail, m_head;
};

}  // namespace Intrusive

}  // namespace PCSX
