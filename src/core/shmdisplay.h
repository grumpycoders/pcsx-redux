/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <atomic>

#include "core/system.h"
#include "support/eventbus.h"
#include "support/sharedmem.h"

namespace PCSX {

// Publishes the emulated display and accepts pad input through a shared memory block, so that a host
// application can show the running game in its own window. Enabled with -shmdisplay. The block is named
// pcsx-redux-display-<pid>, as a POSIX shm object or a Windows file mapping.
//
// The block starts with ShmDisplayHeader, and a copy of the 1024x512 16bpp VRAM follows at vramOffset.
// The header and VRAM are written on each vblank. sequence is odd while a write is in progress, so a
// reader copies what it needs, re-reads sequence, and retries if it changed or was odd.
// The pad words are written by the host. They use the controller's active-low button layout, and are
// ANDed with the emulated controller input while hostInput is non-zero.
struct ShmDisplayHeader {
    static constexpr uint32_t c_magic = 0x44535850;  // "PXSD"
    static constexpr uint32_t c_version = 1;

    uint32_t magic;
    uint32_t version;
    uint32_t headerSize;
    uint32_t vramOffset;
    std::atomic<uint32_t> sequence;
    uint32_t frame;
    int32_t displayX, displayY, displayWidth, displayHeight;
    uint32_t displayDepth24;
    uint32_t displayEnabled;
    std::atomic<uint32_t> hostInput;
    std::atomic<uint32_t> hostPads[2];
};
static_assert(std::atomic<uint32_t>::is_always_lock_free && sizeof(std::atomic<uint32_t>) == 4);

class ShmDisplay {
  public:
    static constexpr size_t c_vramOffset = 4096;
    static constexpr size_t c_vramSize = 1024 * 512 * 2;

    ShmDisplay();
    uint16_t hostPad(int port) const;

  private:
    void publish();

    SharedMem m_mem;
    ShmDisplayHeader* m_header = nullptr;
    EventBus::Listener m_listener;
};

}  // namespace PCSX
