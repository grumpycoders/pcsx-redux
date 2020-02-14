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

#include "support/list.h"

#include <algorithm>

#include "gtest/gtest.h"

struct Element;
typedef PCSX::Intrusive::List<Element> ListType;
struct Element : public ListType::Node {
    Element(int tag = 0) : m_tag(tag) {}
    int m_tag = 0;
};

TEST(BasicList, EmptyList) {
    ListType list;
    EXPECT_TRUE(list.empty());
}

TEST(BasicList, PushBackIterator) {
    ListType list;
    list.push_back(new Element(1));
    list.push_back(new Element(2));
    list.push_back(new Element(3));
    EXPECT_FALSE(list.empty());

    ListType::iterator i = list.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 2);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}

TEST(BasicList, PushFrontIterator) {
    ListType list;
    list.push_front(new Element(1));
    list.push_front(new Element(2));
    list.push_front(new Element(3));
    EXPECT_FALSE(list.empty());

    ListType::iterator i = list.end();
    i--;
    EXPECT_EQ(i->m_tag, 1);
    i--;
    EXPECT_EQ(i->m_tag, 2);
    i--;
    EXPECT_EQ(i->m_tag, 3);
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}

TEST(AlgorithmList, FindIf) {
    ListType list;
    list.push_back(new Element(1));
    list.push_back(new Element(2));
    list.push_back(new Element(3));

    auto i = list.begin();
    auto f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 1; });
    EXPECT_TRUE(f == i);
    EXPECT_EQ(f->m_tag, 1);
    i++;
    f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 2; });
    EXPECT_TRUE(f == i);
    EXPECT_EQ(f->m_tag, 2);
    i++;
    f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 3; });
    EXPECT_TRUE(f == i);
    EXPECT_EQ(f->m_tag, 3);
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}
