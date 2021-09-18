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
#include "support/hashtable.h"

static constexpr uint32_t SEED = 2891583007UL;

static uint32_t someRand(uint32_t& a) {
    a ^= 61;
    a ^= a >> 16;
    a += a << 3;
    a ^= a >> 4;
    a *= 668265263UL;
    a ^= a >> 15;
    a *= 3148259783UL;
    return a;
}

struct TreeElement;
typedef PCSX::Intrusive::Tree<uint32_t, TreeElement> TreeType;
typedef PCSX::Intrusive::HashTable<uint32_t, TreeElement> HashTableType;
struct TreeElement : public TreeType::Node, public HashTableType::Node {
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
    static constexpr unsigned COUNT = 10;
    static constexpr uint32_t P = 999999929;

    TreeType tree;
    uint32_t v;

    v = 0;
    for (unsigned i = 0; i < COUNT; i++) {
        tree.insert(v & 255, new TreeElement(v));
        v += P;
    }

    EXPECT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), COUNT);

    v = 0;
    for (unsigned i = 0; i < COUNT / 2; i++) {
        auto it = tree.find(v & 255);
        EXPECT_FALSE(it == tree.end());
        EXPECT_EQ(it->m_tag, v);
        delete &*it;
        v += P;
        v += P;
    }

    EXPECT_EQ(tree.size(), COUNT / 2);

    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
}

TEST(BasicTree, RandomElements) {
    static constexpr unsigned COUNT = 25000;

    TreeType tree;

    uint32_t seed;
    seed = SEED;
    for (unsigned i = 0; i < COUNT; i++) {
        uint32_t v = someRand(seed);
        tree.insert(v, new TreeElement(v));
    }

    const uint32_t fullSeed = seed;

    EXPECT_FALSE(tree.empty());
    EXPECT_EQ(tree.size(), COUNT);

    seed = SEED;
    for (unsigned i = 0; i < COUNT / 2; i++) {
        uint32_t v = someRand(seed);
        auto it = tree.find(v);
        EXPECT_FALSE(it == tree.end());
        EXPECT_EQ(it->m_tag, v);
        delete &*it;
    }

    const uint32_t midSeed = seed;

    seed = fullSeed;
    for (unsigned i = 0; i < COUNT; i++) {
        uint32_t v = someRand(seed);
        tree.insert(v, new TreeElement(v));
    }

    EXPECT_EQ(tree.size(), COUNT + COUNT / 2);

    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
}

TEST(IntervalTree, BasicInterval) {
    TreeType tree;
    auto e0 = tree.insert(16, 21, new TreeElement(0));
    auto e1 = tree.insert(8, 9, new TreeElement(1));
    auto e2 = tree.insert(25, 30, new TreeElement(2));
    auto e3 = tree.insert(5, 8, new TreeElement(3));
    auto e4 = tree.insert(15, 23, new TreeElement(4));
    auto e5 = tree.insert(17, 19, new TreeElement(5));
    auto e6 = tree.insert(26, 26, new TreeElement(6));
    auto e7 = tree.insert(0, 3, new TreeElement(7));
    auto e8 = tree.insert(6, 10, new TreeElement(8));
    auto e9 = tree.insert(19, 20, new TreeElement(9));

    EXPECT_EQ(tree.size(), 10);

    HashTableType hashtable;

    auto i = tree.find(18, 19);
    while (i != tree.end()) {
        hashtable.insert(i->m_tag, &*i);
        i++;
    }

    EXPECT_EQ(hashtable.size(), 4);
    EXPECT_TRUE(hashtable.contains(&*e0));
    EXPECT_TRUE(hashtable.contains(&*e4));
    EXPECT_TRUE(hashtable.contains(&*e5));
    EXPECT_TRUE(hashtable.contains(&*e9));

    hashtable.clear();
    auto j = tree.find(10, 15);
    while (j != tree.end()) {
        hashtable.insert(j->m_tag, &*j);
        j++;
    }

    EXPECT_EQ(hashtable.size(), 2);
    EXPECT_TRUE(hashtable.contains(&*e4));
    EXPECT_TRUE(hashtable.contains(&*e8));

    tree.destroyAll();
    EXPECT_TRUE(tree.empty());
    EXPECT_TRUE(hashtable.empty());
}

TEST(IntervalTree, Disjoint) {
    TreeType tree;
    auto e0 = tree.insert(10, 20, new TreeElement(0));
    auto e1 = tree.insert(30, 40, new TreeElement(1));

    EXPECT_EQ(tree.size(), 2);

    HashTableType hashtable;

    {
        auto i = tree.find(20, 30);
        while (i != tree.end()) {
            hashtable.insert(i->m_tag, &*i);
            i++;
        }

        EXPECT_EQ(hashtable.size(), 2);
    }
    hashtable.clear();

    {
        auto i = tree.find(50, 60);
        while (i != tree.end()) {
            hashtable.insert(i->m_tag, &*i);
            i++;
        }

        EXPECT_EQ(hashtable.size(), 0);
    }
    hashtable.clear();

    {
        auto i = tree.find(5, 6);
        while (i != tree.end()) {
            hashtable.insert(i->m_tag, &*i);
            i++;
        }
        EXPECT_EQ(hashtable.size(), 0);
    }

    tree.destroyAll();
}

TEST(IntervalTree, Fuzzy) {
    TreeType tree;
    auto e0 = tree.insert(10, 20, new TreeElement(0));
    auto e1 = tree.insert(30, 40, new TreeElement(1));

    EXPECT_EQ(tree.size(), 2);

    {
        auto i = tree.find(10);
        EXPECT_NE(i, tree.end());
    }

    {
        auto i = tree.find(15);
        EXPECT_EQ(i, tree.end());
    }

    HashTableType hashtable;
    {
        auto i = tree.find(15, TreeType::INTERVAL_SEARCH);
        while (i != tree.end()) {
            hashtable.insert(i->m_tag, &*i);
            i++;
        }
        EXPECT_EQ(hashtable.size(), 1);
    }

    tree.destroyAll();
}
