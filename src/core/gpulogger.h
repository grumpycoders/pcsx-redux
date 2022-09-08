/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "core/gpu.h"
#include "support/eventbus.h"
#include "support/slice.h"

namespace PCSX {

namespace Widgets {
class GPULogger;
}

class GPULogger {
  public:
    GPULogger();
    void clearFrameLog() { m_list.destroyAll(); }
    template <typename T>
    void addNode(const T& data, GPU::Logged::Origin origin, uint32_t value, uint32_t length) {
        if (m_enabled) {
            T* node = new T(data);
            addNodeInternal(new T(data), origin, value, length);
        }
    }
    void replay(GPU*);

  private:
    void startNewFrame();
    void addNodeInternal(GPU::Logged* node, GPU::Logged::Origin, uint32_t value, uint32_t length);

    EventBus::Listener m_listener;
    bool m_enabled = false;
    bool m_breakOnVSync = false;
    uint64_t m_frameCounter = 0;
    GPU::LoggedList m_list;
    Slice m_vram;
    friend class Widgets::GPULogger;
};

}  // namespace PCSX
