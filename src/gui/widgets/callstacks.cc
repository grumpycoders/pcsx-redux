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
#include "supportpsx/memory.h"

static void drawSymbol(uint32_t pc) {
    std::pair<const uint32_t, std::string>* symbol = PCSX::g_emulator->m_cpu->findContainingSymbol(pc);
    if (symbol) {
        auto symbolNameBegin = symbol->second.data();
        auto symbolNameEnd = symbolNameBegin + symbol->second.size();
        ImGui::SameLine();
        ImGui::TextUnformatted(" :: ");
        ImGui::SameLine();
        ImGui::TextUnformatted(symbolNameBegin, symbolNameEnd);
        ImGui::SameLine();
        ImGui::Text("+0x%08x", pc - symbol->first);
    }
}

void PCSX::Widgets::CallStacks::draw(const char* title, PCSX::GUI* gui) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    gui->useMonoFont();

    ImGui::TextUnformatted("    low SP    -   high sp  ");
    ImGui::TextUnformatted("      ra      :: stack pointer ::  stack frame  :: ra symbol");
    ImGui::Separator();

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
        int callId = 0;
        for (auto& call : stack.calls) {
            ImGui::PushID(callId++);
            std::string label = fmt::format("0x{:08x}##lowsp", call.ra);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{call.ra});
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(" :: ");
            ImGui::SameLine();
            label = fmt::format("0x{:08x}##highsp", call.sp);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{call.sp, 4});
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(" :: ");
            ImGui::SameLine();
            label = fmt::format("0x{:08x}##frame", call.fp);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{call.fp, 1});
            }
            drawSymbol(call.ra);
            ImGui::PopID();
        }
        if (stack.ra != 0) {
            std::string label = fmt::format("0x{:08x}##ralowsp", stack.ra);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{stack.ra});
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(" :: ");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
            ImGui::TextUnformatted("<heuristic>");
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextUnformatted(" :: ");
            ImGui::SameLine();
            label = fmt::format("0x{:08x}##raframe", stack.fp);
            if (ImGui::Button(label.c_str())) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{stack.fp, 1});
            }
            drawSymbol(stack.ra);
        }
        ImGui::TreePop();
    }
    ImGui::PopFont();
    ImGui::End();
}
