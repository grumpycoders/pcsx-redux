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

#include <any>
#include <functional>
#include <typeindex>
#include <typeinfo>
#include <utility>

#include "support/hashtable.h"
#include "support/list.h"

namespace PCSX {

namespace EventBus {

struct ListenerElementBaseEventBusList {};
struct ListenerElementBase;
typedef PCSX::Intrusive::List<ListenerElementBase> ListenerBaseListType;
typedef PCSX::Intrusive::List<ListenerElementBase, ListenerElementBaseEventBusList> ListenerBaseEventBusList;
struct ListenerElementBase : public ListenerBaseListType::Node, public ListenerBaseEventBusList::Node {
    virtual void* getCB() = 0;
};
template <typename M>
struct ListenerElement : public ListenerElementBase {
    virtual void* getCB() { return &cb; }
    ListenerElement(std::function<void(const M&)>&& cb) : cb(std::move(cb)) {}
    std::function<void(const M)> cb;
};

class EventBus;

class Listener {
  public:
    Listener(std::shared_ptr<EventBus> bus) : m_bus(bus) {}
    ~Listener() { m_listeners.destroyAll(); }
    template <typename Event>
    void listen(std::function<void(const Event&)>&& cb);

  private:
    std::shared_ptr<EventBus> m_bus;
    ListenerBaseEventBusList m_listeners;
};

struct ListenerElementsHashTableList;
typedef PCSX::Intrusive::HashTable<std::size_t, ListenerElementsHashTableList> ListenersHashTable;
struct ListenerElementsHashTableList : public ListenersHashTable::Node {
    ~ListenerElementsHashTableList() { list.destroyAll(); }
    ListenerBaseEventBusList list;
};

class EventBus {
  public:
    ~EventBus() { m_table.destroyAll(); }
    template <typename Event>
    void signal(const Event& event) {
        using funcType = std::function<void(const Event&)>;
        auto list = m_table.find(typeid(Event).hash_code());
        if (list == m_table.end()) return;
        for (auto& listener : list->list) {
            void* cb = listener.getCB();
            funcType* func = static_cast<funcType*>(cb);
            (*func)(event);
        }
    }

  private:
    void listen(std::size_t id, ListenerElementBase* listenerElement) {
        auto list = m_table.find(id);
        if (list == m_table.end()) {
            list = m_table.insert(id, new ListenerElementsHashTableList());
        }
        list->list.push_back(listenerElement);
    }
    ListenersHashTable m_table;
    friend class Listener;
};

template <typename Event>
void Listener::listen(std::function<void(const Event&)>&& cb) {
    ListenerElement<Event>* element = new ListenerElement(std::move(cb));
    m_listeners.push_back(element);
    m_bus->listen(typeid(Event).hash_code(), element);
}

}  // namespace EventBus

}  // namespace PCSX
