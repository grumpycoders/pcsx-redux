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

#include "core/patchmanager.h"
#include "core/r3000a.h"
#include "gui/widgets/patches.h"
#include "imgui.h"

void PCSX::Widgets::Patches::draw(const char* title) {
    ImGui::SetNextWindowPos(ImVec2(520, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (PCSX::g_emulator->m_cpu->isDynarec()) {
        ImGui::TextUnformatted(_("Patching is only available in Interpreted CPU mode"));
        ImGui::End();
        return;
    }

    static ImGuiTableFlags flags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
                            ImGuiTableFlags_ContextMenuInBody;

    if (ImGui::BeginTable("Patches", 4, flags)) {
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Active");
        ImGui::TableSetupColumn("Type");
        ImGui::TableHeadersRow();

        PatchManager& patchManager = *PCSX::g_emulator->m_patchManager;

        int deleteIndex = -1;
        int numPatches = patchManager.getNumPatches();
        for (int row = 0; row < numPatches; row++) {
            PCSX::PatchManager::Patch& patch = patchManager.getPatch(row);
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            char buf[256];
            sprintf(buf, "%d", row);
            ImGui::TextUnformatted(buf);

            ImGui::TableSetColumnIndex(1);
            sprintf(buf, "%08x", patch.addr);

            if (ImGui::Button(buf, ImVec2(-FLT_MIN, 0.0f))) {
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{patch.addr});
            }
            if (ImGui::BeginPopupContextItem()) {
                ImGui::TextUnformatted("Delete Patch?");
                if (ImGui::Button("Delete")) {
                    deleteIndex = row;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::PushID(row);
            if (ImGui::Checkbox("", &patch.active))
            {
                if (patch.active)
                {
                    patchManager.doPatch(row);
                }
                else
                {
                    patchManager.undoPatch(row);
                }
            }
            ImGui::PopID();

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(patch.type == PCSX::PatchManager::Patch::Type::Return ? "Return" : "NOP");
        }
        ImGui::EndTable();

        if (deleteIndex != -1) {
            patchManager.deletePatch(deleteIndex);
        }

        if (ImGui::Button("Activate All")) {
            patchManager.activateAll();
        }

        ImGui::SameLine();
        if (ImGui::Button("Deactivate All")) {
            patchManager.deactivateAll();
        }

        ImGui::SameLine();
        if (ImGui::Button("Delete All")) {
            patchManager.deleteAllPatches();
        }
    }
   
    ImGui::End();
}
