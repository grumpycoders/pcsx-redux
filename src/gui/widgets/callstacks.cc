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

#include "gui/widgets/callstacks.h"

#include "core/callstacks.h"
#include "core/psxemulator.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"

void PCSX::Widgets::CallStacks::draw(const char* title, PCSX::GUI* gui) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    gui->useMonoFont();

    auto& callstacks = g_emulator->m_callStacks;
    auto& current = callstacks->getCurrent();

    for (auto& stack : callstacks->getCallstacks()) {
        uint32_t low = stack.getLow();
        uint32_t high = stack.getHigh();
        if (stack.calls.size() == 0) continue;
        bool isCurrent = &current == &stack;
        std::string label = fmt::format("0x{:08x} - 0x{:08x}", low, high);
        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_Bullet | ImGuiTreeNodeFlags_DefaultOpen;
        if (isCurrent) flags |= ImGuiTreeNodeFlags_Selected;
        if (!ImGui::TreeNodeEx(label.c_str(), flags)) continue;
        for (auto& call : stack.calls) {
            std::string label = fmt::format("0x{:08x}", call.ra);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{call.ra});
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(" :: ");
            ImGui::SameLine();
            label = fmt::format("0x{:08x}", call.sp);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{call.sp});
            }
        }
        ImGui::TreePop();
    }
    ImGui::PopFont();
    ImGui::End();
}
