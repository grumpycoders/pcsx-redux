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

#include "core/gpulogger.h"

#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"

PCSX::GPULogger::GPULogger() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::GPU::VSync>([this](auto event) {
        if (m_breakOnVSync) {
            g_system->pause();
        }
        if (m_enabled) m_clearScheduled = true;
    });
}

void PCSX::GPULogger::addNodeInternal(GPU::Logged* node, GPU::Logged::Origin origin, uint32_t value, uint32_t length) {
    node->origin = origin;
    node->value = value;
    node->length = length;
    node->pc = g_emulator->m_cpu->m_regs.pc;
    m_list.push_back(node);
}

void PCSX::GPULogger::startNewFrame() {
    clearFrameLog();
    m_vram = g_emulator->m_gpu->getVRAM(GPU::Ownership::ACQUIRE);
}

void PCSX::GPULogger::replay(GPU* gpu) {
    gpu->partialUpdateVRAM(0, 0, 1024, 512, m_vram.data<uint16_t>());
    for (auto& node : m_list) {
        if (node.enabled) node.execute(gpu);
    }
    gpu->vblank(true);
}
