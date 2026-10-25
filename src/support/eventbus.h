/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <any>
#include <functional>
#include <memory>
#include <utility>

#include "support/hashtable.h"
#include "support/list.h"

#if defined(_CPPRTTI) || defined(__GXX_RTTI) || defined(__cpp_rtti)
#define PCSX_RTTI 1
#include <typeindex>
#include <typeinfo>
#define PCSX_HASH_TYPE(type) typeid(type).hash_code()
#else
#define PCSX_RTTI 0
#define CTTI_HAS_ENUM_AWARE_PRETTY_FUNCTION 1
#include "ctti/type_id.hpp"
#define PCSX_HASH_TYPE(type) ctti::unnamed_type_id<type>().hash()
#endif

namespace PCSX {

namespace EventBus {

#if PCSX_RTTI
typedef std::size_t HashType;
#else
typedef std::uint64_t HashType;
#endif

struct ListenerElementBaseEventBusList {};
struct ListenerElementBase;
typedef PCSX::Intrusive::List<ListenerElementBase> ListenerBaseListType;
typedef PCSX::Intrusive::List<ListenerElementBase, ListenerElementBaseEventBusList> ListenerBaseEventBusList;
struct ListenerElementBase : public ListenerBaseListType::Node, public ListenerBaseEventBusList::Node {
    virtual std::any getCB() = 0;
    bool m_dead = false;
};
template <typename M>
struct ListenerElement : public ListenerElementBase {
    typedef std::function<void(const M&)> Functor;
    virtual std::any getCB() { return &cb; }
    ListenerElement(Functor&& cb) : cb(std::move(cb)) {}
    Functor cb;
};

class EventBus;

class Listener {
  public:
    Listener(std::shared_ptr<EventBus> bus) : m_bus(bus) {}
    ~Listener();
    template <typename Event>
    void listen(typename ListenerElement<Event>::Functor&& cb);

  private:
    std::shared_ptr<EventBus> m_bus;
    ListenerBaseListType m_listeners;
};

struct ListenerElementsHashTableList;
typedef PCSX::Intrusive::HashTable<HashType, ListenerElementsHashTableList> ListenersHashTable;
struct ListenerElementsHashTableList : public ListenersHashTable::Node {
    ~ListenerElementsHashTableList() { list.destroyAll(); }
    ListenerBaseEventBusList list;
};

class EventBus {
  public:
    ~EventBus() { m_table.destroyAll(); }
    template <typename Event>
    void signal(const Event& event) {
        using Functor = typename ListenerElement<Event>::Functor;
        auto list = m_table.find(PCSX_HASH_TYPE(Event));
        if (list == m_table.end()) return;
        // A callback may destroy listeners, including its own. Those are only
        // flagged while we are dispatching, and freed once the outermost
        // signal returns, so the iteration and the running closure stay valid.
        struct DispatchGuard {
            DispatchGuard(EventBus* bus) : bus(bus) { bus->m_dispatching++; }
            ~DispatchGuard() {
                // Stay nonzero while freeing: a closure's destructor may signal or drop listeners.
                if (bus->m_dispatching == 1) bus->m_graveyard.destroyAll();
                bus->m_dispatching--;
            }
            EventBus* bus;
        } guard(this);
        for (auto& listener : list->list) {
            if (listener.m_dead) continue;
            std::any cb = listener.getCB();
            Functor* func = std::any_cast<Functor*>(cb);
            (*func)(event);
        }
    }

  private:
    void listen(HashType id, ListenerElementBase* listenerElement) {
        auto list = m_table.find(id);
        if (list == m_table.end()) {
            list = m_table.insert(id, new ListenerElementsHashTableList());
        }
        list->list.push_back(listenerElement);
    }
    ListenersHashTable m_table;
    ListenerBaseListType m_graveyard;
    unsigned m_dispatching = 0;
    friend class Listener;
};

inline Listener::~Listener() {
    if (m_bus->m_dispatching == 0) {
        m_listeners.destroyAll();
        return;
    }
    while (!m_listeners.empty()) {
        auto& element = *m_listeners.begin();
        element.m_dead = true;
        m_bus->m_graveyard.push_back(&element);
    }
}

template <typename Event>
void Listener::listen(typename ListenerElement<Event>::Functor&& cb) {
    ListenerElement<Event>* element = new ListenerElement(std::move(cb));
    m_listeners.push_back(element);
    m_bus->listen(PCSX_HASH_TYPE(Event), element);
}

}  // namespace EventBus

}  // namespace PCSX
