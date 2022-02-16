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

#include <string>

#include "GL/gl3w.h"
#include "clip/clip.h"
#include "core/sio.h"
#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

namespace PCSX {

class GUI;
namespace Widgets {

class MemcardManager {
  public:
    bool draw(GUI* gui, const char* title);
    bool m_show = false;
    // The framecount from 0 to 59 inclusive. We need it to know which frame of multi-animation
    // icons to display.
    int m_frameCount = 0;

    MemcardManager();
    void initTextures();

  private:
    int m_selectedCard = 1;
    int m_iconSize = 32;  // The width and length of the icon images
    int m_selectedBlock;
    bool m_showMemoryEditor = false;
    bool m_drawPocketstationIcons = false;
    uint8_t* m_currentCardData = (uint8_t*)g_emulator->m_sio->GetMcdData(m_selectedCard);

    GLuint m_iconTextures[15];
    MemoryEditor m_memoryEditor;

    enum class Actions { None, Format, Move, Copy, Swap };
    struct {
        Actions type = Actions::None;
        // The block from m_selectedCard we will use as our source
        int sourceBlock;
        // The memory card (1 or 2) our operation will target
        int targetCard;
        // Buffer to store the title for our action popups
        std::string popupText = "";
        // Buffer to store user-provided block numbers. Needs to store 2 digits + a null terminator, so 3 chars
        char textInput[3] = "";
    } m_pendingAction;

    clip::image getIconRGBA8888(int blockNumber, const SIO::McdBlock& block);

    void drawIcon(int blockNumber, const SIO::McdBlock& block);
    void exportPNG(int blockNumber, const SIO::McdBlock& block);
    void copyToClipboard(int blockNumber, const SIO::McdBlock& block);
    void getPocketstationIcon(uint32_t* pixels, int blockNumber);
    void performAction();
};

}  // namespace Widgets
}  // namespace PCSX
