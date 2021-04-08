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

#include "gui/widgets/events.h"

#include "core/kernel.h"
#include "core/psxemulator.h"
#include "core/system.h"
#include "imgui.h"

void PCSX::Widgets::Events::draw(const uint32_t* psxMemory, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                             ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    auto events = Kernel::Events::getAllEvents(psxMemory);
    if (ImGui::BeginTable("Events", 6, flags)) {
        ImGui::TableSetupColumn(_("ID"));
        ImGui::TableSetupColumn(_("Core"));
        ImGui::TableSetupColumn(_("Spec"));
        ImGui::TableSetupColumn(_("Mode"));
        ImGui::TableSetupColumn(_("Flag"));
        ImGui::TableSetupColumn(_("CB"));
        ImGui::TableHeadersRow();
        for (auto& ev : events) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%08x", ev.getId());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", ev.getClass().c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", ev.getSpec().c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s", ev.getMode().c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s", ev.getFlag().c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%08x", ev.getCB());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}
