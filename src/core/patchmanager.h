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

#pragma once

#include <stdint.h>
#include <vector>

namespace PCSX {

class PatchManager {
  public:
    struct Patch {
        enum class Type : uint8_t { None, Return, NOP };

        Patch(uint32_t addr, Type type, uint32_t org0, uint32_t org1) {
            this->addr = addr;
            this->org0 = org0;
            this->org1 = org1;
            this->type = type;
        }

        uint32_t addr;
        uint32_t org0;
        uint32_t org1;
        bool active = true;
        Type type;
    };

    int getNumPatches() const { return (int)m_patches.size(); }
    Patch& getPatch(int index) { return m_patches[index]; }

    int registerPatch(uint32_t address, Patch::Type type);
    PatchManager::Patch::Type findPatch(uint32_t address) const;
    void deletePatch(uint32_t index);
    void deleteAllPatches();
    void deactivateAll();
    void activateAll();

    void doPatch(int index) { doPatch(m_patches[index]); }
    void undoPatch(int index) { undoPatch(m_patches[index]); }

  private:
    void doPatch(Patch& patch);
    void undoPatch(Patch& patch);

    std::vector<Patch> m_patches;
};

}  // namespace PCSX
