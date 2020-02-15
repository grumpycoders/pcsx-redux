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
    EXPECT_EQ(list.size(), 3);

    ListType::iterator i = list.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 2);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list.end());
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}

TEST(BasicList, PushFrontIterator) {
    ListType list;
    list.push_front(new Element(1));
    list.push_front(new Element(2));
    list.push_front(new Element(3));
    EXPECT_FALSE(list.empty());
    EXPECT_EQ(list.size(), 3);

    ListType::iterator i = list.end();
    i--;
    EXPECT_EQ(i->m_tag, 1);
    i--;
    EXPECT_EQ(i->m_tag, 2);
    i--;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(i == list.begin());
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}

TEST(AdvancedList, MoveElement) {
    ListType list;
    list.push_back(new Element(1));
    list.push_back(new Element(2));
    list.push_back(new Element(3));

    auto i = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 2; });
    list.push_front(&*i);
    EXPECT_EQ(list.size(), 3);
    i = list.begin();
    EXPECT_EQ(i->m_tag, 2);
    i++;
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list.end());
    list.destroyAll();
}

TEST(AdvancedList, TwoListsExclusive) {
    ListType list1;
    ListType list2;

    Element *e1, *e2, *e3;

    list1.push_back(e1 = new Element(1));
    list1.push_back(e2 = new Element(2));
    list1.push_back(e3 = new Element(3));

    auto i = std::find_if(list1.begin(), list1.end(), [](Element& e) { return e.m_tag == 2; });
    list2.push_front(&*i);
    EXPECT_EQ(list1.size(), 2);
    i = list1.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list1.end());

    EXPECT_EQ(list2.size(), 1);
    i = list2.begin();
    EXPECT_EQ(i->m_tag, 2);
    EXPECT_TRUE(++i == list2.end());

    EXPECT_TRUE(e1->isLinked());
    EXPECT_TRUE(e2->isLinked());
    EXPECT_TRUE(e3->isLinked());

    EXPECT_TRUE(list1.contains(e1));
    EXPECT_FALSE(list1.contains(e2));
    EXPECT_TRUE(list1.contains(e3));

    EXPECT_FALSE(list2.contains(e1));
    EXPECT_TRUE(list2.contains(e2));
    EXPECT_FALSE(list2.contains(e3));

    list1.destroyAll();
    list2.destroyAll();
}

TEST(AdvancedList, ListSwap) {
    ListType list1, list2;
    Element *e1, *e2, *e3;

    list1.push_back(e1 = new Element(1));
    list2.push_back(e2 = new Element(2));
    list1.push_back(e3 = new Element(3));

    EXPECT_EQ(list1.size(), 2);
    auto i = list1.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list1.end());

    EXPECT_EQ(list2.size(), 1);
    i = list2.begin();
    EXPECT_EQ(i->m_tag, 2);
    EXPECT_TRUE(++i == list2.end());

    EXPECT_TRUE(list1.contains(e1));
    EXPECT_FALSE(list1.contains(e2));
    EXPECT_TRUE(list1.contains(e3));

    EXPECT_FALSE(list2.contains(e1));
    EXPECT_TRUE(list2.contains(e2));
    EXPECT_FALSE(list2.contains(e3));

    list1.swap(list2);

    EXPECT_EQ(list2.size(), 2);
    i = list2.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list2.end());

    EXPECT_EQ(list1.size(), 1);
    i = list1.begin();
    EXPECT_EQ(i->m_tag, 2);
    EXPECT_TRUE(++i == list1.end());

    EXPECT_TRUE(list2.contains(e1));
    EXPECT_FALSE(list2.contains(e2));
    EXPECT_TRUE(list2.contains(e3));

    EXPECT_FALSE(list1.contains(e1));
    EXPECT_TRUE(list1.contains(e2));
    EXPECT_FALSE(list1.contains(e3));
}

TEST(AdvancedList, Append) {
    ListType list1, list2;
    Element *e1, *e2, *e3;

    list1.push_back(e1 = new Element(1));
    list2.push_back(e2 = new Element(2));
    list1.push_back(e3 = new Element(3));

    ListType swap;
    swap.append(list1);
    list1.append(list2);
    list2.append(swap);
    EXPECT_EQ(list2.size(), 2);
    auto i = list2.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list2.end());

    EXPECT_EQ(list1.size(), 1);
    i = list1.begin();
    EXPECT_EQ(i->m_tag, 2);
    EXPECT_TRUE(++i == list1.end());

    EXPECT_TRUE(list2.contains(e1));
    EXPECT_FALSE(list2.contains(e2));
    EXPECT_TRUE(list2.contains(e3));

    EXPECT_FALSE(list1.contains(e1));
    EXPECT_TRUE(list1.contains(e2));
    EXPECT_FALSE(list1.contains(e3));
}

TEST(AdvancedList, Prepend) {
    ListType list1, list2;
    Element *e1, *e2, *e3;

    list1.push_back(e1 = new Element(1));
    list2.push_back(e2 = new Element(2));
    list1.push_back(e3 = new Element(3));

    ListType swap;
    swap.prepend(list1);
    list1.prepend(list2);
    list2.prepend(swap);
    EXPECT_EQ(list2.size(), 2);
    auto i = list2.begin();
    EXPECT_EQ(i->m_tag, 1);
    i++;
    EXPECT_EQ(i->m_tag, 3);
    EXPECT_TRUE(++i == list2.end());

    EXPECT_EQ(list1.size(), 1);
    i = list1.begin();
    EXPECT_EQ(i->m_tag, 2);
    EXPECT_TRUE(++i == list1.end());

    EXPECT_TRUE(list2.contains(e1));
    EXPECT_FALSE(list2.contains(e2));
    EXPECT_TRUE(list2.contains(e3));

    EXPECT_FALSE(list1.contains(e1));
    EXPECT_TRUE(list1.contains(e2));
    EXPECT_FALSE(list1.contains(e3));
}

TEST(AlgorithmList, FindIf) {
    ListType list;
    list.push_back(new Element(1));
    auto e1 = --list.end();
    list.push_back(new Element(2));
    auto e2 = --list.end();
    list.push_back(new Element(3));
    auto e3 = --list.end();

    auto i = list.begin();
    auto f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 1; });
    EXPECT_TRUE(f == i);
    EXPECT_TRUE(f == e1);
    EXPECT_EQ(f->m_tag, 1);
    i++;
    f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 2; });
    EXPECT_TRUE(f == i);
    EXPECT_TRUE(f == e2);
    EXPECT_EQ(f->m_tag, 2);
    i++;
    f = std::find_if(list.begin(), list.end(), [](Element& e) { return e.m_tag == 3; });
    EXPECT_TRUE(f == i);
    EXPECT_TRUE(f == e3);
    EXPECT_EQ(f->m_tag, 3);
    list.destroyAll();
    EXPECT_TRUE(list.empty());
}
