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

#include "gui/widgets/handlers.h"

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/system.h"
#include "fmt/format.h"
#include "imgui.h"

void PCSX::Widgets::Handlers::draw(const uint32_t* psxMemory, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    uint32_t* data = reinterpret_cast<uint32_t*>(PSXM(0x100));

    if (!data) {
        ImGui::End();
        return;
    }

    const unsigned count = data[1] / 8;
    uint32_t* array = reinterpret_cast<uint32_t*>(PSXM(SWAP_LE32(data[0])));

    if (!array) {
        ImGui::Text(_("Invalid data at 0x100"));
        ImGui::End();
        return;
    }

    unsigned counter = 0;

    for (unsigned priority = 0; priority < count; priority++) {
        ImGui::Text(_("Priority %i"), priority);
        uint32_t infoAddr = SWAP_LE32(array[priority]);
        if (!infoAddr) {
            ImGui::TextUnformatted(_("  No handlers"));
            ImGui::Separator();
            continue;
        }
        while (infoAddr) {
            uint32_t* infoPtr = reinterpret_cast<uint32_t*>(PSXM(infoAddr));
            if (!infoPtr) {
                ImGui::Text(_("  Corrupted info"));
                break;
            }
            std::string buttonStr;
            ImGui::TextUnformatted(_("  Handler data at "));
            ImGui::SameLine();
            buttonStr = fmt::format("{:08x}##{}", infoAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToMemory{infoAddr, 16});
            }
            ImGui::Text(_("  verifier: "));
            ImGui::SameLine();
            uint32_t verifierAddr = SWAP_LE32(infoPtr[2]);
            buttonStr = fmt::format("{:08x}##{}", verifierAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToPC{verifierAddr});
            }
            ImGui::Text(_("  handler: "));
            ImGui::SameLine();
            uint32_t handlerAddr = SWAP_LE32(infoPtr[1]);
            buttonStr = fmt::format("{:08x}##{}", handlerAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToPC{handlerAddr});
            }
            infoAddr = SWAP_LE32(infoPtr[0]);
        }
        ImGui::Separator();
    }

    ImGui::End();
}
