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

#include <string>
#include <vector>

namespace PCSX {

class Memory;

namespace Widgets {

class HeapViewer {
  public:
    HeapViewer(bool& show) : m_show(show) {}
    void draw(Memory* memory, const char* title);

    bool& m_show;

  private:
    struct Block {
        uint32_t address;
        uint32_t size;
        bool free;
    };

    struct WalkResult {
        std::vector<Block> blocks;
        std::string error;
    };

    WalkResult walkHeap(Memory* memory);
};

}  // namespace Widgets
}  // namespace PCSX
