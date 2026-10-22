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

#include "core/shmdisplay.h"

#include <atomic>
#include <cstring>

#include "core/gpu.h"
#include "core/psxemulator.h"

PCSX::ShmDisplay::ShmDisplay() : m_listener(g_system->m_eventBus) {
    static_assert(sizeof(ShmDisplayHeader) <= c_vramOffset);
    if (!m_mem.init("display", c_vramOffset + c_vramSize, true)) {
        g_system->message(_("Failed to create the shared display memory block\n"));
    }
    m_header = reinterpret_cast<ShmDisplayHeader*>(m_mem.getPtr());
    m_header->magic = ShmDisplayHeader::c_magic;
    m_header->version = ShmDisplayHeader::c_version;
    m_header->headerSize = sizeof(ShmDisplayHeader);
    m_header->vramOffset = c_vramOffset;
    m_header->hostPads[0] = m_header->hostPads[1] = 0xffff;
    m_listener.listen<Events::GPU::VSync>([this](const auto& event) { publish(); });
}

void PCSX::ShmDisplay::publish() {
    auto& sequence = m_header->sequence;
    sequence.fetch_add(1, std::memory_order_acq_rel);

    auto& gpu = g_emulator->m_gpu;
    auto vram = gpu->getVRAM();
    std::memcpy(m_mem.getPtr() + c_vramOffset, vram.data(), std::min<size_t>(vram.size(), c_vramSize));
    auto& display = gpu->m_display;
    m_header->displayX = display.start.x();
    m_header->displayY = display.start.y();
    m_header->displayWidth = display.size.x();
    m_header->displayHeight = display.size.y();
    m_header->displayDepth24 = display.info.depth == GPU::CtrlDisplayMode::CD_24BITS ? 1 : 0;
    m_header->displayEnabled = (gpu->readStatus() & (1 << 23)) ? 0 : 1;
    m_header->frame++;

    sequence.fetch_add(1, std::memory_order_acq_rel);
}

uint16_t PCSX::ShmDisplay::hostPad(int port) const {
    if (m_header->hostInput.load(std::memory_order_acquire) == 0) return 0xffff;
    return m_header->hostPads[port].load(std::memory_order_relaxed);
}
