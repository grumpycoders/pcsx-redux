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
        virtual void bumpMax(const BaseNode* o) = 0;
        virtual void setMax(const BaseNode* o) = 0;
        virtual void rebaseMaxToHigh() = 0;
        friend class BaseTree;
        BaseNode *m_left = nullptr, *m_right = nullptr, *m_parent = nullptr;
        enum class Color { BLACK, RED } m_color = Color::BLACK;
        BaseTree* m_tree = nullptr;
        const BaseNode* next() const { return m_tree->next(this); }
        const BaseNode* prev() const { return m_tree->prev(this); }
        BaseNode* next() { return m_tree->next(this); }
        BaseNode* prev() { return m_tree->prev(this); }
    };

    BaseTree(BaseNode* nil) : m_nil(nil), m_root(nil) {}
    virtual ~BaseTree() {}

    const BaseNode* next(const BaseNode*) const;
    const BaseNode* prev(const BaseNode*) const;
    BaseNode* next(BaseNode*) const;
    BaseNode* prev(BaseNode*) const;

    void leftRotate(BaseNode* const x);
    void rightRotate(BaseNode* const x);
    void insertInternal(BaseNode* const z);
    void insertFixup(BaseNode* z);
    void transplant(BaseNode* u, BaseNode* v);
    void deleteInternal(BaseNode* const z);
    void deleteFixup(BaseNode* x);

    unsigned m_count = 0;
    BaseNode* m_root = nullptr;
    BaseNode* const m_nil = nullptr;
};

template <typename Key, class T>
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
            Tree<Key, T>* tree = dynamic_cast<Tree<Key, T>*>(m_tree);
            tree->unlink(this);
        }
        const Key& getLow() { return m_low; }
        const Key& getHigh() { return m_high; }

      private:
        int cmp(const Key& o) const {
            if (m_low < o) return -1;
            if (m_low == o) return 0;
            return 1;
        }
        virtual int cmp(const BaseNode* o_) const final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            return cmp(o->m_low);
        }
        virtual void bumpMax(const BaseNode* o_) final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            m_max = std::max(m_max, o->m_max);
        }
        virtual void setMax(const BaseNode* o_) final override {
            const Node* o = dynamic_cast<const Node*>(o_);
            m_max = o->m_max;
        }
        virtual void rebaseMaxToHigh() final override { m_max = m_high; }
        friend class Tree;
        Key m_low, m_high, m_max;
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
            m_node = dynamic_cast<Base*>(m_node->next());
            return *this;
        }
        IteratorBase operator++(int) {
            IteratorBase copy(*this);
            m_node = dynamic_cast<Base*>(m_node->next());
            return copy;
        }
        IteratorBase& operator--() {
            m_node = dynamic_cast<Base*>(m_node->prev());
            return *this;
        }
        IteratorBase operator--(int) {
            IteratorBase copy(*this);
            m_node = dynamic_cast<Base*>(m_node->prev());
            return copy;
        }

        friend class Tree;

        Base* m_node = nullptr;
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
    }

    unsigned size() { return m_count; }
    iterator begin() {
        BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return iterator(dynamic_cast<Node*>(min));
    }
    const_iterator begin() const {
        const BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(dynamic_cast<const Node*>(min));
    }
    const_iterator cbegin() const {
        const BaseNode* min = m_root;
        while (min->m_left != &m_nil) min = min->m_left;
        return const_iterator(dynamic_cast<const Node*>(min));
    }
    iterator end() { return iterator(&m_nil); }
    const_iterator end() const { return const_iterator(&m_nil); }
    const_iterator cend() const { return const_iterator(&m_nil); }
    bool empty() const { return m_count == 0; }
    void clear() {
        while (m_count) unlink(m_root);
    }
    iterator insert(const Key& key, Node* const z) {
        z->unlink();
        z->m_low = key;
        z->m_high = key;
        z->m_max = key;
        z->m_tree = this;

        insertInternal(z);

        m_count++;
        return iterator(z);
    }
    iterator find(const Key& key) {
        Node cmp;
        cmp.m_low = key;
        BaseNode* p = m_root;
        int c;
        while ((p != &m_nil) && ((c = p->cmp(&cmp)) != 0)) {
            p = c < 0 ? p->m_right : p->m_left;
        }
        return dynamic_cast<Node*>(p);
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
    bool contains(Node* node) { return this == node->m_root; }
    void destroyAll() {
        while (m_count) delete m_root;
    }
};

}  // namespace Intrusive

}  // namespace PCSX
