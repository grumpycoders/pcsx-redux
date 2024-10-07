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

    IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();

    uint32_t arrayPointer = memFile->readAt<uint32_t>(0x100);
    const unsigned count = memFile->readAt<uint32_t>(0x104) / 8;

    if (!arrayPointer) {
        ImGui::TextUnformatted(_("Invalid data at 0x100"));
        ImGui::End();
        return;
    }
    ImGui::Text(_("Handlers info at %08x"), arrayPointer);

    unsigned counter = 0;

    for (unsigned priority = 0; priority < count; priority++) {
        std::string priorityStr = fmt::format(f_("Priority {}"), priority);
        if (!ImGui::TreeNode(priorityStr.c_str())) {
            continue;
        }
        uint32_t infoAddr = memFile->readAt<uint32_t>(arrayPointer + priority * 8);
        if (!infoAddr) {
            ImGui::TextUnformatted(_("No handlers"));
            ImGui::TreePop();
            continue;
        }
        while (infoAddr) {
            std::string buttonStr;
            ImGui::TextUnformatted(_("Handler data at "));
            ImGui::SameLine();
            buttonStr = fmt::format("{:08x}##{}", infoAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToMemory{infoAddr, 16});
            }
            ImGui::TextUnformatted(_("  verifier: "));
            ImGui::SameLine();
            uint32_t verifierAddr = memFile->readAt<uint32_t>(infoAddr + 8);
            buttonStr = fmt::format("{:08x}##{}", verifierAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToPC{verifierAddr});
            }
            ImGui::TextUnformatted(_("  handler: "));
            ImGui::SameLine();
            uint32_t handlerAddr = memFile->readAt<uint32_t>(infoAddr + 4);
            buttonStr = fmt::format("{:08x}##{}", handlerAddr, counter++);
            if (ImGui::Button(buttonStr.c_str())) {
                g_system->m_eventBus->signal(Events::GUI::JumpToPC{handlerAddr});
            }
            infoAddr = memFile->readAt<uint32_t>(infoAddr);
        }
        ImGui::TreePop();
    }

    ImGui::End();
}
