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

class BaseTree {
  protected:
    class BaseNode {
      public:
        virtual ~BaseNode() {}
        virtual int cmp(const BaseNode* o) const = 0;
        virtual bool overlaps(const BaseNode* o) const = 0;
        virtual bool overlapsMax(const BaseNode* o) const = 0;
        virtual void bumpMinMax(const BaseNode* o) = 0;
        virtual void setMinMax(const BaseNode* o) = 0;
        virtual void rebaseMaxToHigh() = 0;
        friend class BaseTree;
        BaseNode *m_left = nullptr, *m_right = nullptr, *m_parent = nullptr;
        enum class Color { BLACK, RED } m_color = Color::BLACK;
        BaseTree* m_tree = nullptr;
        const BaseNode* next(const BaseNode* interval) const { return m_tree->next(this, interval); }
        BaseNode* next(const BaseNode* interval) { return m_tree->next(this, interval); }
    };

    BaseTree(BaseNode* nil) : m_nil(nil), m_root(nil) {}
    virtual ~BaseTree() {}

    const BaseNode* next(const BaseNode*, const BaseNode* interval) const;
    const BaseNode* prev(const BaseNode*, const BaseNode* interval) const;
    BaseNode* next(BaseNode*, const BaseNode* interval) const;
    BaseNode* prev(BaseNode*, const BaseNode* interval) const;

    void leftRotate(BaseNode* const x);
    void rightRotate(BaseNode* const x);
    void insertInternal(BaseNode* const z);
    void insertFixup(BaseNode* z);
    void transplant(BaseNode* u, BaseNode* v);
    void deleteInternal(BaseNode* const z);
    void deleteFixup(BaseNode* x);
    void regenerateMinMax(BaseNode* x);

    unsigned m_count = 0;
    BaseNode* m_root = nullptr;
    BaseNode* const m_nil = nullptr;
};

template <typename Key, class T, class limits = std::numeric_limits<Key>>
class Tree final : public BaseTree {
  public:
    class Node : public BaseTree::BaseNode {
      public:
        Node() {}
        Node(const Node&) = delete;
        Node& operator=(const Node&) = delete;
        Node(Node&& src) = delete;
        virtual ~Node() { unlink(); }
        bool isLinked() const { return m_tree; }
        void unlink() {
            if (!isLinked()) return;
            Tree<Key, T, limits>* tree = dynamic_cast<Tree<Key, T, limits>*>(m_tree);
            tree->unlink(this);
        }
        const Key& getLow() const { return m_low; }
        const Key& getHigh() const { return m_high; }

      private:
        int cmpMin(const Key& o) const {
            if (m_min < o) return -1;
            if (m_min == o) return 0;
            return 1;
        }
        int cmpLow(const Key& o) const {
            if (m_low < o) return -1;
            if (m_low == o) return 0;
            return 1;
        }
        int cmpHigh(const Key& o) const {
            if (m_high < o) return -1;
            if (m_high == o) return 0;
            return 1;
        }
        int cmpMax(const Key& o) const {
            if (m_max < o) return -1;
            if (m_max == o) return 0;
            return 1;
        }
        virtual int cmp(const BaseNode* o_) const final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            return cmpLow(o->m_low);
        }
        virtual bool overlaps(const BaseNode* o_) const final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            return cmpLow(o->m_high) <= 0 && cmpHigh(o->m_low) >= 0;
        }
        virtual bool overlapsMax(const BaseNode* o_) const final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            return cmpMin(o->m_high) <= 0 && cmpMax(o->m_low) >= 0;
        }
        virtual void bumpMinMax(const BaseNode* o_) final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            m_min = std::min(m_min, o->m_min);
            m_max = std::max(m_max, o->m_max);
        }
        virtual void setMinMax(const BaseNode* o_) final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            m_min = o->m_min;
            m_max = o->m_max;
        }
        virtual void rebaseMaxToHigh() final override {
            m_min = m_low;
            m_max = m_high;
        }
        friend class Tree;
        Key m_low, m_high, m_min, m_max;
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

        IteratorBase(const IteratorBase& src) : m_node(src.m_node) {
            m_interval.m_min = src.m_interval.m_min;
            m_interval.m_low = src.m_interval.m_low;
            m_interval.m_high = src.m_interval.m_high;
            m_interval.m_max = src.m_interval.m_max;
        }
        IteratorBase& operator=(const IteratorBase& src) {
            m_node = src.m_node;
            m_interval.m_min = src.m_interval.m_min;
            m_interval.m_low = src.m_interval.m_low;
            m_interval.m_high = src.m_interval.m_high;
            m_interval.m_max = src.m_interval.m_max;
            return *this;
        }
        IteratorBase(Base* node, Base& interval) : m_node(node) {
            static_assert(std::is_base_of<Base, Derived>::value);
            m_interval.m_min = interval.m_min;
            m_interval.m_low = interval.m_low;
            m_interval.m_high = interval.m_high;
            m_interval.m_max = interval.m_max;
        }
        template <class srcDerived, class srcBase>
        IteratorBase(const IteratorBase<srcDerived, srcBase>& src) : m_node(src.m_node), m_interval(src.m_interval) {}
        template <class srcDerived, class srcBase>
        IteratorBase& operator=(const IteratorBase<srcDerived, srcBase>& src) {
            m_node = src.m_node;
            m_interval.m_min = src.m_interval.m_min;
            m_interval.m_low = src.m_interval.m_low;
            m_interval.m_high = src.m_interval.m_high;
            m_interval.m_max = src.m_interval.m_max;
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
            m_node = dynamic_cast<Base*>(m_node->next(&m_interval));
            return *this;
        }
        IteratorBase operator++(int) {
            IteratorBase copy(m_node, m_interval);
            m_node = dynamic_cast<Base*>(m_node->next(&m_interval));
            return copy;
        }

        friend class Tree;

        Base* m_node = nullptr;
        Node m_interval;
    };

    Node m_nil;

  public:
    typedef IteratorBase<T, Node> iterator;
    typedef IteratorBase<const T, const Node> const_iterator;

    Tree() : BaseTree(&m_nil) {
        Node* nil = &m_nil;
        nil->m_left = nil;
        nil->m_right = nil;
        nil->m_parent = nil;
        nil->m_tree = nullptr;
        nil->m_min = nil->m_low = limits::min();
        nil->m_high = nil->m_max = limits::max();
    }

    unsigned size() const { return m_count; }
    iterator begin() {
        BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return iterator(dynamic_cast<Node*>(min), m_nil);
    }
    const_iterator begin() const {
        const BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(dynamic_cast<const Node*>(min), m_nil);
    }
    const_iterator cbegin() const {
        const BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(dynamic_cast<const Node*>(min), m_nil);
    }
    iterator end() { return iterator(&m_nil, m_nil); }
    const_iterator end() const { return const_iterator(&m_nil, m_nil); }
    const_iterator cend() const { return const_iterator(&m_nil, m_nil); }
    bool empty() const { return m_count == 0; }
    void clear() {
        while (m_count) unlink(dynamic_cast<Node*>(m_root));
    }
    iterator insert(const Key& key, Node* const z) {
        z->unlink();
        z->m_low = key;
        z->m_high = key;
        z->m_min = key;
        z->m_max = key;
        z->m_tree = this;

        insertInternal(z);

        m_count++;
        return iterator(z, m_nil);
    }
    iterator insert(const Key& low, const Key& high, Node* const z) {
        z->unlink();
        z->m_low = low;
        z->m_high = high;
        z->m_min = low;
        z->m_max = high;
        z->m_tree = this;

        insertInternal(z);

        m_count++;
        return iterator(z, m_nil);
    }
    iterator find(const Key& key) {
        Node cmp;
        cmp.m_low = key;
        BaseNode* p = m_root;
        int c;
        while ((p != &m_nil) && ((c = p->cmp(&cmp)) != 0)) {
            p = c < 0 ? p->m_right : p->m_left;
        }
        Node* ptr = p == &m_nil ? &m_nil : dynamic_cast<Node*>(p);
        return iterator(ptr, m_nil);
    }
    const_iterator find(const Key& key) const {
        Node cmp;
        cmp.m_low = key;
        const BaseNode* p = m_root;
        int c;
        while ((p != &m_nil) && ((c = p->cmp(&cmp)) != 0)) {
            p = c < 0 ? p->m_right : p->m_left;
        }
        const Node* ptr = p == &m_nil ? &m_nil : dynamic_cast<const Node*>(p);
        return const_iterator(ptr, m_nil);
    }
    enum IntervalSearch { INTERVAL_SEARCH };
    iterator find(const Key& key, IntervalSearch) { return find(key, key); }
    const_iterator find(const Key& key, IntervalSearch) const { return find(key, key); }
    iterator find(const Key& low, const Key& high) {
        Node interval;
        interval.m_low = interval.m_min = low;
        interval.m_high = interval.m_max = high;
        BaseNode* first = m_root;
        while ((first != &m_nil) && (first->m_left != &m_nil) && first->overlapsMax(&interval)) first = first->m_left;
        Node* ptr = first == &m_nil ? &m_nil : dynamic_cast<Node*>(first);
        iterator ret(ptr, interval);
        if (!ret->overlaps(&interval)) ret++;
        return ret;
    }
    const_iterator find(const Key& low, const Key& high) const {
        Node interval;
        interval.m_low = interval.m_min = low;
        interval.m_high = interval.m_max = high;
        const BaseNode* first = m_root;
        while ((first != &m_nil) && (first->m_left != &m_nil) && first->overlapsMax(&interval)) first = first->m_left;
        const Node* ptr = first == &m_nil ? &m_nil : dynamic_cast<const Node*>(first);
        const_iterator ret(ptr, interval);
        if (!ret->overlaps(&interval)) ret++;
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
        if (!isLinked(node)) return end();
        return iterator(node);
    }
    const_iterator buildConstIterator(Node* node) const {
        if (!contains(node)) return end();
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
