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

#include "GL/gl3w.h"
#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

namespace PCSX {
namespace Widgets {

class MemcardManager {
  public:
    bool draw(const char* title);
    bool m_show = false;
    // The framecount from 0 to 59 inclusive. We need it to know which frame of multi-animation
    // icons to display.
    int m_frameCount = 0;

    MemcardManager();
    void init();

  private:
    int m_selectedCard = 1;
    bool m_showMemoryEditor = false;
    GLuint m_iconTextures[15];
    MemoryEditor m_memoryEditor;

    void drawIcon(int blockNumber, uint16_t* icon);
};

}  // namespace Widgets
}  // namespace PCSX
