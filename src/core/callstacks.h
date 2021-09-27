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

#include <stdint.h>

#include "core/system.h"
#include "support/eventbus.h"
#include "support/list.h"
#include "support/tree.h"

namespace PCSX {

struct SaveStateWrapper;

class CallStacks {
  public:
    struct CallStack;

  private:
    typedef Intrusive::Tree<uint32_t, CallStack> TreeType;
    typedef Intrusive::List<CallStack> ListType;

  public:
    struct CallStack : public TreeType::Node, public ListType::Node {
        struct Call;
        typedef Intrusive::List<Call> ListType;
        struct Call : public ListType::Node {
            Call(uint32_t sp_, uint32_t ra_, bool shadow_) : sp(sp_), ra(ra_), shadow(shadow_) {}
            uint32_t sp, ra;
            bool shadow;
        };
        ~CallStack() { calls.destroyAll(); }
        ListType calls;
        uint32_t ra = 0;
    };

    const CallStack& getCurrent() { return *m_current; }
    const TreeType& getCallstacks() { return m_callstacks; }

    void serialize(SaveStateWrapper*);
    void deserialize(const SaveStateWrapper*);

  private:
    TreeType m_callstacks;
    CallStack* m_current = nullptr;
    uint32_t m_currentSP = 0;

    EventBus::Listener m_listener;

  public:
    CallStacks() : m_listener(g_system->m_eventBus) {
        m_listener.listen<Events::ExecutionFlow::Reset>([this](const auto& event) {
            m_callstacks.clear();
            m_current = nullptr;
            m_currentSP = 0;
        });
    }
    void setSP(uint32_t oldSP, uint32_t newSP);
    void offsetSP(uint32_t oldSP, int32_t offset);
    void storeRA(uint32_t sp, uint32_t ra);
    void loadRA(uint32_t sp);
    void potentialRA(uint32_t ra);
};

}  // namespace PCSX
