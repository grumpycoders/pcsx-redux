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

#include "support/tree.h"

#include <algorithm>

#include "gtest/gtest.h"

struct TreeElement;
typedef PCSX::Intrusive::Tree<uint32_t, TreeElement> TreeType;
struct TreeElement : public TreeType::Node {
    TreeElement(uint32_t tag = 0) : m_tag(tag) {}
    uint32_t m_tag = 0;
};

TEST(BasicTree, EmptyTree) {
    TreeType tree;
    EXPECT_TRUE(tree.empty());
}

TEST(BasicTree, BasicTree) {
    TreeType tree;
    tree.insert(1, new TreeElement(1));
    tree.insert(2, new TreeElement(2));
    tree.insert(3, new TreeElement(3));

    EXPECT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), 3);

    TreeType::iterator i = tree.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 2);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == tree.end());
    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
}

TEST(BasicTree, ManyElements) {
    static constexpr unsigned COUNT = 25000;
    static constexpr uint32_t P = 99999971;

    TreeType tree;
    uint32_t v;

    v = 0;
    for (unsigned i = 0; i < COUNT; i++) {
        tree.insert(v, new TreeElement(v));
        v += P;
    }

    EXPECT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), COUNT);

    v = 0;
    for (unsigned i = 0; i < COUNT; i++) {
        auto it = tree.find(v);
        EXPECT_FALSE(it == tree.end());
        EXPECT_EQ(it->m_tag, v);
        v += P;
    }

    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
}

TEST(BasicTree, Shuffle) {
    static constexpr unsigned COUNT = 250;
    static constexpr uint32_t P = 999999929;

    TreeType tree;
    uint32_t v;

    v = 0;
    for (unsigned i = 0; i < COUNT; i++) {
        tree.insert(v, new TreeElement(v));
        v += P;
    }

    EXPECT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), COUNT);

    v = 0;
    for (unsigned i = 0; i < COUNT / 2; i++) {
        auto it = tree.find(v);
        EXPECT_FALSE(it == tree.end());
        EXPECT_EQ(it->m_tag, v);
        delete &*it;
        v += P;
        v += P;
    }

    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
}
