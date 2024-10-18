/***************************************************************************
 *   Copyright (C) 2024 PCSX-Redux authors                                 *
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

#include "patchmanager.h"
#include "core/psxmem.h"
#include "core/psxemulator.h"

extern PCSX::Emulator* g_emulator;

int PCSX::PatchManager::registerPatch(uint32_t address, Patch::Type type) {
    int index = (int)m_patches.size();
    uint32_t org0 = g_emulator->m_mem->read32(address);
    uint32_t org1 = (type == Patch::Type::Return) ? g_emulator->m_mem->read32(address + 4) : 0;
    Patch patch = Patch(address, type, org0, org1);
    doPatch(patch);
    m_patches.push_back(patch);
    std::sort(m_patches.begin(), m_patches.end(), [](Patch const& a, Patch const& b) { return a.addr < b.addr; });
    return index;
}

void PCSX::PatchManager::doPatch(Patch& patch) {
    switch (patch.type) {
        case PatchManager::Patch::Type::Return:
            g_emulator->m_mem->write32(patch.addr, 0x03e00008);
            g_emulator->m_mem->write32(patch.addr + 4, 0);
            break;

        case PatchManager::Patch::Type::NOP:
            g_emulator->m_mem->write32(patch.addr, 0);
            break;

        default:
            return;
    }
    patch.active = true;
}

void PCSX::PatchManager::undoPatch(Patch& patch) {
    switch (patch.type) {
        case PatchManager::Patch::Type::Return:
            g_emulator->m_mem->write32(patch.addr, patch.org0);
            g_emulator->m_mem->write32(patch.addr + 4, patch.org1);
            break;

        case PatchManager::Patch::Type::NOP:
            g_emulator->m_mem->write32(patch.addr, patch.org0);
            break;

        default:
            return;
    }
    patch.active = false;
}

PCSX::PatchManager::Patch::Type PCSX::PatchManager::findPatch(uint32_t address) {
    int idx = 0;
    for (std::vector<Patch>::iterator it = m_patches.begin(); it != m_patches.end(); ++it) {
        if (it->addr == address) {
            return it->type;
        }
        idx++;
    }
    return PCSX::PatchManager::Patch::Type::None;
}

void PCSX::PatchManager::deletePatch(uint32_t index) {
    undoPatch(m_patches[index]);
    m_patches.erase(m_patches.begin() + index);
}

void PCSX::PatchManager::deleteAllPatches() {
    deactivateAll();
    m_patches.clear();
}

void PCSX::PatchManager::deactivateAll() {
    int idx = 0;
    for (std::vector<Patch>::iterator it = m_patches.begin(); it != m_patches.end(); ++it) {
        if (it->active) {
            undoPatch(m_patches[idx]);
        }
        idx++;
    }
}

void PCSX::PatchManager::activateAll() {
    int idx = 0;
    for (std::vector<Patch>::iterator it = m_patches.begin(); it != m_patches.end(); ++it) {
        if (!it->active) {
            doPatch(m_patches[idx]);
        }
        idx++;
    }
}
