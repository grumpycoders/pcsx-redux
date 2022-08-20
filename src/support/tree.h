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

#include <assert.h>

#include <algorithm>
#include <iterator>
#include <type_traits>

namespace PCSX {

namespace Intrusive {

template <typename Key, class T, class limits = std::numeric_limits<Key>>
class Tree final {
    struct Interval {
        Interval() : low(limits::min()), high(limits::max()), min(limits::min()), max(limits::min()) {}
        Interval(Key key) : low(key), high(key), min(key), max(key) {}
        Interval(Key low_, Key high_) : low(low_), high(high_), min(low_), max(high_) {}
        Interval(const Interval&) = default;
        Interval(Interval&&) = default;
        Interval& operator=(const Interval&) = default;
        Key low, high, min, max;
    };

  public:
    class Node {
      public:
        Node() {}
        Node(const Node&) {}
        Node& operator=(const Node&) { unlink(); }
        Node(Node&& src) = delete;
        virtual ~Node() { unlink(); }
        bool isLinked() const { return m_tree; }
        void unlink() {
            if (!isLinked()) return;
            m_tree->unlink(this);
        }
        const Key& getLow() const { return m_interval.low; }
        const Key& getHigh() const { return m_interval.high; }

      private:
        int cmpMin(const Key& o) const {
            if (m_interval.min < o) return -1;
            if (m_interval.min == o) return 0;
            return 1;
        }
        int cmpLow(const Key& o) const {
            if (m_interval.low < o) return -1;
            if (m_interval.low == o) return 0;
            return 1;
        }
        int cmpHigh(const Key& o) const {
            if (m_interval.high < o) return -1;
            if (m_interval.high == o) return 0;
            return 1;
        }
        int cmpMax(const Key& o) const {
            if (m_interval.max < o) return -1;
            if (m_interval.max == o) return 0;
            return 1;
        }
        int cmp(const Interval& i) const { return cmpLow(i.low); }
        bool overlaps(const Interval& i) const { return cmpLow(i.high) <= 0 && cmpHigh(i.low) >= 0; }
        bool overlapsMax(const Interval& i) const { return cmpMin(i.high) <= 0 && cmpMax(i.low) >= 0; }
        void bumpMinMax(const Interval& i) {
            m_interval.min = std::min(m_interval.min, i.min);
            m_interval.max = std::max(m_interval.max, i.max);
        }
        void setMinMax(const Interval& i) {
            m_interval.min = i.min;
            m_interval.max = i.max;
        }
        void rebaseMaxToHigh() {
            m_interval.min = m_interval.low;
            m_interval.max = m_interval.high;
        }
        const Node* next(const Interval& interval) const { return m_tree->next(this, interval); }
        Node* next(const Interval& interval) { return m_tree->next(this, interval); }

        friend class Tree<Key, T, limits>;
        Node *m_left = nullptr, *m_right = nullptr, *m_parent = nullptr;
        Tree<Key, T, limits>* m_tree = nullptr;
        Interval m_interval;
        enum class Color { BLACK, RED } m_color = Color::BLACK;
    };

  private:
    // This code is basically a mindless implementation of
    // "Introduction to Algorithms, 3rd Edition", chapters 12 and 14.
    // The interval trees from chapter 14 had to be heavily adapted,
    // in order to properly maintain the max attribute.

    const Node* next(const Node* x, const Interval& interval) const {
        const Node* y;
        do {
            y = x->m_right;
            if (y != &m_nil && y->overlapsMax(interval)) {
                while (y->m_left != &m_nil) y = y->m_left;
            } else {
                y = x->m_parent;
                while ((y != &m_nil) && (x == y->m_right)) {
                    x = y;
                    y = y->m_parent;
                }
            }
            x = y;
        } while ((x != &m_nil) && !x->overlaps(interval));
        return x;
    }
    Node* next(Node* x, const Interval& interval) const {
        Node* y;
        do {
            y = x->m_right;
            if (y != &m_nil && y->overlapsMax(interval)) {
                while (y->m_left != &m_nil) y = y->m_left;
            } else {
                y = x->m_parent;
                while ((y != &m_nil) && (x == y->m_right)) {
                    x = y;
                    y = y->m_parent;
                }
            }
            x = y;
        } while ((x != &m_nil) && !x->overlaps(interval));
        return x;
    }

    void leftRotate(Node* const x) {
        Node* const y = x->m_right;
        x->m_right = y->m_left;
        if (y->m_left != &m_nil) y->m_left->m_parent = x;
        y->m_parent = x->m_parent;
        if (x->m_parent == &m_nil) {
            m_root = y;
        } else if (x == x->m_parent->m_left) {
            x->m_parent->m_left = y;
        } else {
            x->m_parent->m_right = y;
        }
        y->m_left = x;
        x->m_parent = y;
        y->setMinMax(x->m_interval);
        regenerateMinMax(x);
    }
    void rightRotate(Node* const x) {
        Node* const y = x->m_left;
        x->m_left = y->m_right;
        if (y->m_right != &m_nil) y->m_right->m_parent = x;
        y->m_parent = x->m_parent;
        if (x->m_parent == &m_nil) {
            m_root = y;
        } else if (x == x->m_parent->m_right) {
            x->m_parent->m_right = y;
        } else {
            x->m_parent->m_left = y;
        }
        y->m_right = x;
        x->m_parent = y;
        y->setMinMax(x->m_interval);
        regenerateMinMax(x);
    }
    void insertInternal(Node* const z) {
        Node* y = &m_nil;
        Node* x = m_root;
        while (x != &m_nil) {
            y = x;
            y->bumpMinMax(z->m_interval);
            if (z->cmp(x->m_interval) < 0) {
                x = x->m_left;
            } else {
                x = x->m_right;
            }
        }
        z->m_parent = y;
        if (y == &m_nil) {
            m_root = z;
        } else if (z->cmp(y->m_interval) < 0) {
            y->m_left = z;
        } else {
            y->m_right = z;
        }
        z->m_left = &m_nil;
        z->m_right = &m_nil;
        z->m_color = Node::Color::RED;
        insertFixup(z);
    }
    void insertFixup(Node* z) {
        while (z->m_parent->m_color == Node::Color::RED) {
            if (z->m_parent == z->m_parent->m_parent->m_left) {
                Node* y = z->m_parent->m_parent->m_right;
                if (y->m_color == Node::Color::RED) {
                    z->m_parent->m_color = Node::Color::BLACK;
                    y->m_color = Node::Color::BLACK;
                    z = z->m_parent->m_parent;
                    z->m_color = Node::Color::RED;
                } else {
                    if (z == z->m_parent->m_right) {
                        z = z->m_parent;
                        leftRotate(z);
                    }
                    z->m_parent->m_color = Node::Color::BLACK;
                    z->m_parent->m_parent->m_color = Node::Color::RED;
                    rightRotate(z->m_parent->m_parent);
                }
            } else {
                Node* y = z->m_parent->m_parent->m_left;
                if (y->m_color == Node::Color::RED) {
                    z->m_parent->m_color = Node::Color::BLACK;
                    y->m_color = Node::Color::BLACK;
                    z = z->m_parent->m_parent;
                    if (z != &m_nil) z->m_color = Node::Color::RED;
                } else {
                    if (z == z->m_parent->m_left) {
                        z = z->m_parent;
                        rightRotate(z);
                    }
                    z->m_parent->m_color = Node::Color::BLACK;
                    z->m_parent->m_parent->m_color = Node::Color::RED;
                    leftRotate(z->m_parent->m_parent);
                }
            }
        }
        m_root->m_color = Node::Color::BLACK;
    }
    void transplant(Node* u, Node* v) {
        if (u->m_parent == &m_nil) {
            m_root = v;
        } else if (u == u->m_parent->m_left) {
            u->m_parent->m_left = v;
        } else {
            u->m_parent->m_right = v;
        }
        v->m_parent = u->m_parent;
    }
    void deleteInternal(Node* const z) {
        Node* y = z;
        Node* x = nullptr;

        auto o = y->m_color;
        if (z->m_left == &m_nil) {
            x = z->m_right;
            transplant(z, z->m_right);
            regenerateMinMax(z->m_parent);
        } else if (z->m_right == &m_nil) {
            x = z->m_left;
            transplant(z, z->m_left);
            regenerateMinMax(z->m_parent);
        } else {
            y = z->m_right;
            while (y->m_left != &m_nil) y = y->m_left;
            o = y->m_color;
            x = y->m_right;
            if (y->m_parent == z) {
                x->m_parent = y;
            } else {
                transplant(y, y->m_right);
                y->m_right = z->m_right;
                y->m_right->m_parent = y;
            }
            transplant(z, y);
            y->m_left = z->m_left;
            y->m_left->m_parent = y;
            y->m_color = z->m_color;
            regenerateMinMax(y);
        }
        regenerateMinMax(x);
        if (o == Node::Color::BLACK) deleteFixup(x);
    }
    void deleteFixup(Node* x) {
        while ((x != m_root) && (x->m_color == Node::Color::BLACK)) {
            if (x == x->m_parent->m_left) {
                Node* w = x->m_parent->m_right;
                if (w->m_color == Node::Color::RED) {
                    w->m_color = Node::Color::BLACK;
                    x->m_parent->m_color = Node::Color::RED;
                    leftRotate(x->m_parent);
                    w = x->m_parent->m_right;
                }
                if ((w->m_left->m_color == Node::Color::BLACK) && (w->m_right->m_color == Node::Color::BLACK)) {
                    w->m_color = Node::Color::RED;
                    x = x->m_parent;
                } else {
                    if (w->m_right->m_color == Node::Color::BLACK) {
                        w->m_left->m_color = Node::Color::BLACK;
                        w->m_color = Node::Color::RED;
                        rightRotate(w);
                        w = x->m_parent->m_right;
                    }
                    w->m_color = x->m_parent->m_color;
                    x->m_parent->m_color = Node::Color::BLACK;
                    w->m_right->m_color = Node::Color::BLACK;
                    leftRotate(x->m_parent);
                    x = m_root;
                }
            } else {
                Node* w = x->m_parent->m_left;
                if (w->m_color == Node::Color::RED) {
                    w->m_color = Node::Color::BLACK;
                    x->m_parent->m_color = Node::Color::RED;
                    rightRotate(x->m_parent);
                    w = x->m_parent->m_left;
                }
                if ((w->m_right->m_color == Node::Color::BLACK) && (w->m_left->m_color == Node::Color::BLACK)) {
                    w->m_color = Node::Color::RED;
                    x = x->m_parent;
                } else {
                    if (w->m_left->m_color == Node::Color::BLACK) {
                        w->m_right->m_color = Node::Color::BLACK;
                        w->m_color = Node::Color::RED;
                        leftRotate(w);
                        w = x->m_parent->m_left;
                    }
                    w->m_color = x->m_parent->m_color;
                    x->m_parent->m_color = Node::Color::BLACK;
                    w->m_left->m_color = Node::Color::BLACK;
                    rightRotate(x->m_parent);
                    x = m_root;
                }
            }
        }
        x->m_color = Node::Color::BLACK;
    }
    void regenerateMinMax(Node* x) {
        while (x != &m_nil) {
            x->rebaseMaxToHigh();
            if (x->m_left != &m_nil) x->bumpMinMax(x->m_left->m_interval);
            if (x->m_right != &m_nil) x->bumpMinMax(x->m_right->m_interval);
            x = x->m_parent;
        }
    }

    unsigned m_count = 0;
    Node* m_root = nullptr;

    template <class Derived, class Base>
    class IteratorBase final {
      public:
        typedef std::forward_iterator_tag iterator_category;
        typedef Derived value_type;
        typedef ptrdiff_t difference_type;
        typedef Derived* pointer;
        typedef Derived& reference;

        IteratorBase(const IteratorBase& src) = default;
        IteratorBase& operator=(const IteratorBase& src) = default;
        IteratorBase(Base* node) : m_node(node) { static_assert(std::is_base_of<Base, Derived>::value); }
        IteratorBase(Base* node, Interval& interval) : m_node(node) {
            static_assert(std::is_base_of<Base, Derived>::value);
            m_interval = interval;
        }
        template <class srcDerived, class srcBase>
        IteratorBase(const IteratorBase<srcDerived, srcBase>& src) : m_node(src.m_node), m_interval(src.m_interval) {}
        template <class srcDerived, class srcBase>
        IteratorBase& operator=(const IteratorBase<srcDerived, srcBase>& src) {
            m_node = src.m_node;
            m_interval = src.m_interval;
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
            m_node = m_node->next(m_interval);
            return *this;
        }
        IteratorBase operator++(int) {
            IteratorBase copy(m_node, m_interval);
            m_node = m_node->next(m_interval);
            return copy;
        }

        friend class Tree;

        Base* m_node = nullptr;
        Interval m_interval;
    };

  public:
    typedef IteratorBase<T, Node> iterator;
    typedef IteratorBase<const T, const Node> const_iterator;

  private:
    Node m_nil;
    iterator m_end = nullptr;
    const_iterator m_cend = nullptr;

  public:
    Tree() {
        Node* nil = &m_nil;
        nil->m_left = nil;
        nil->m_right = nil;
        nil->m_parent = nil;
        nil->m_tree = nullptr;
        m_root = nil;

        m_end = iterator(&m_nil);
        m_cend = const_iterator(&m_nil);
    }

    unsigned size() const { return m_count; }
    iterator begin() {
        Node* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return iterator(min);
    }
    const_iterator begin() const {
        const Node* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(min);
    }
    const_iterator cbegin() const {
        const Node* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(min);
    }
    iterator end() { return m_end; }
    const_iterator end() const { return m_cend; }
    const_iterator cend() const { return m_cend; }
    bool empty() const { return m_count == 0; }
    void clear() {
        while (m_count) unlink(m_root);
    }
    iterator insert(const Key& key, Node* const z) {
        z->unlink();
        z->m_interval = Interval(key);
        z->m_tree = this;

        insertInternal(z);

        m_count++;
        return iterator(z);
    }
    iterator insert(const Key& low, const Key& high, Node* const z) {
        z->unlink();
        z->m_interval = Interval(low, high);
        z->m_tree = this;

        insertInternal(z);

        m_count++;
        return iterator(z);
    }
    iterator find(const Key& key) {
        Interval cmp;
        cmp.low = key;
        Node* p = m_root;
        int c;
        while ((p != &m_nil) && ((c = p->cmp(cmp)) != 0)) {
            p = c < 0 ? p->m_right : p->m_left;
        }
        return iterator(p);
    }
    const_iterator find(const Key& key) const {
        Interval cmp;
        cmp.low = key;
        const Node* p = m_root;
        int c;
        while ((p != &m_nil) && ((c = p->cmp(cmp)) != 0)) {
            p = c < 0 ? p->m_right : p->m_left;
        }
        return const_iterator(p);
    }
    enum IntervalSearch { INTERVAL_SEARCH };
    iterator find(const Key& key, IntervalSearch) { return find(key, key); }
    const_iterator find(const Key& key, IntervalSearch) const { return find(key, key); }
    iterator find(const Key& low, const Key& high) {
        Interval interval(low, high);
        Node* first = m_root;
        while ((first != &m_nil) && (first->m_left != &m_nil) && first->overlapsMax(interval)) first = first->m_left;
        iterator ret(first, interval);
        if (!ret->overlaps(interval)) ret++;
        return ret;
    }
    const_iterator find(const Key& low, const Key& high) const {
        Interval interval(low, high);
        const Node* first = m_root;
        while ((first != &m_nil) && (first->m_left != &m_nil) && first->overlapsMax(interval)) first = first->m_left;
        const_iterator ret(first, interval);
        if (!ret->overlaps(interval)) ret++;
        return ret;
    }
    iterator erase(iterator i) {
        Node* node = i.m_node;
        i++;
        unlink(node);
        return i;
    }
    void merge(iterator i, Tree& tree) {
        while (!tree.empty()) insert(&*tree.begin());
    }
    void swap(Tree& tree) { std::swap(m_root, tree.m_root); }
    iterator buildIterator(Node* node) const {
        if (!isLinked(node)) return m_end;
        return iterator(node);
    }
    const_iterator buildConstIterator(Node* node) const {
        if (!contains(node)) return m_cend;
        return const_iterator(node);
    }
    void unlink(Node* const z) {
        if (z->m_tree != this) return;

        assert(z != &m_nil);

        deleteInternal(z);
        z->m_tree = nullptr;

        m_count--;
    }
    bool contains(Node* node) const { return this == node->m_root; }
    void destroyAll() {
        while (m_count) delete m_root;
    }
};

}  // namespace Intrusive

}  // namespace PCSX
