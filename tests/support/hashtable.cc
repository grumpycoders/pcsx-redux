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

#include "support/hashtable.h"

#include <algorithm>

#include "gtest/gtest.h"

struct HashElement;
typedef PCSX::Intrusive::HashTable<int, HashElement> HashTableType;
struct HashElement : public HashTableType::Node {
    HashElement(int tag = 0) : m_tag(tag) {}
    int m_tag = 0;
};

TEST(BasicHashTable, EmptyHashTable) {
    HashTableType hashtab;
    EXPECT_TRUE(hashtab.empty());
}

TEST(BasicHashTable, InsertOne) {
    HashTableType hashtab;
    hashtab.insert(42, new HashElement(42));
    EXPECT_FALSE(hashtab.empty());
    auto p = hashtab.find(42);
    EXPECT_FALSE(p == hashtab.end());
    HashElement& n = *p;
    EXPECT_EQ(n.getKey(), 42);
    EXPECT_EQ(n.m_tag, 42);
    hashtab.destroyAll();
    EXPECT_TRUE(hashtab.empty());
}

TEST(BasicHashTable, InsertMany) {
    HashTableType hashtab;
    for (unsigned i = 0; i < 42; i++) {
        hashtab.insert(i, new HashElement(i));
    }
    EXPECT_EQ(hashtab.size(), 42);
    for (unsigned i = 0; i < 42; i++) {
        auto p = hashtab.find(i);
        EXPECT_FALSE(p == hashtab.end());
        HashElement& n = *p;
        EXPECT_EQ(n.getKey(), i);
        EXPECT_EQ(n.m_tag, i);
    }

    hashtab.destroyAll();
    EXPECT_TRUE(hashtab.empty());
}

TEST(BasicHashTable, UseAfterDestroy) {
    HashTableType hashtab;
    for (unsigned i = 0; i < 42; i++) {
        hashtab.insert(i, new HashElement(i));
    }
    hashtab.destroyAll();
    for (unsigned i = 0; i < 42; i++) {
        hashtab.insert(100 + i, new HashElement(100 + i));
    }
    EXPECT_EQ(hashtab.size(), 42);
    for (unsigned i = 0; i < 42; i++) {
        auto p = hashtab.find(100 + i);
        EXPECT_FALSE(p == hashtab.end());
        HashElement& n = *p;
        EXPECT_EQ(n.getKey(), 100 + i);
        EXPECT_EQ(n.m_tag, 100 + i);
    }

    hashtab.destroyAll();
    EXPECT_TRUE(hashtab.empty());
}
TEST(AdvancedHashTable, Eviction) {
    HashTableType hashtab;
    HashElement* e1 = new HashElement(1);
    HashElement* e2 = new HashElement(2);

    hashtab.insert(42, e1);
    hashtab.insert(42, e2);

    EXPECT_EQ(hashtab.size(), 1);
    EXPECT_FALSE(hashtab.contains(e1));
    EXPECT_TRUE(hashtab.contains(e2));
    EXPECT_FALSE(e1->isLinked());
    EXPECT_TRUE(e2->isLinked());

    auto i = hashtab.find(42);
    EXPECT_EQ(i->m_tag, 2);
    hashtab.destroyAll();
    delete e1;
}
TEST(AdvancedHashTable, Iterator) {
    HashTableType hashtab;
    for (unsigned i = 0; i < 64; i++) {
        hashtab.insert(i, new HashElement(i));
    }
    EXPECT_EQ(hashtab.size(), 64);
    uint64_t seen = 0;

    for (auto& i : hashtab) {
        int tag = i.m_tag;
        EXPECT_FALSE(seen & (1ULL << tag));
        seen |= (1ULL << tag);
    }

    EXPECT_EQ(seen, 0xffffffffffffffffULL);

    hashtab.destroyAll();
}
