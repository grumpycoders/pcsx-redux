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

struct Element;
typedef PCSX::Intrusive::HashTable<int, Element> HashTableType;
struct Element : public HashTableType::Node {
    Element(int tag = 0) : m_tag(tag) {}
    int m_tag = 0;
};

TEST(BasicHashTable, EmptyHashTable) {
    HashTableType hashtab;
    EXPECT_TRUE(hashtab.empty());
}

TEST(BasicHashTable, Insert) {
    HashTableType hashtab;
    hashtab.insert(42, new Element(42));
    EXPECT_FALSE(hashtab.empty());
    hashtab.destroyAll();
    EXPECT_TRUE(hashtab.empty());
}
