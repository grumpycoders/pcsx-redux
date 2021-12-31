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

#include "core/sio.h"
#include "core/system.h"
#include "gui/widgets/memcard_manager.h"

PCSX::Widgets::MemcardManager::MemcardManager() {
    m_memoryEditor.OptShowDataPreview = true;
    m_memoryEditor.OptUpperCaseHex = false;
}

bool PCSX::Widgets::MemcardManager::draw(const char* title) {
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(600, 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(400, 400), ImGuiCond_FirstUseEver);

    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return false;
    }

    // Insert or remove memory cards. Send a SIO IRQ to the emulator if this happens as well.
    if (ImGui::Checkbox(_("Memory Card 1 inserted"),
                        &g_emulator->settings.get<Emulator::SettingMcd1Inserted>().value)) {
        g_emulator->m_sio->interrupt();
        changed = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox(_("Memory Card 2 inserted"),
                        &g_emulator->settings.get<Emulator::SettingMcd2Inserted>().value)) {
        g_emulator->m_sio->interrupt();
        changed = true;
    }
    ImGui::Checkbox(_("Show memory card contents"), &m_showMemoryEditor);

    static const char* cardNames[] = {_("Memory card 1"), _("Memory card 2")};
    // Code below is slightly odd because m_selectedCart is 1-indexed while arrays are 0-indexed
    if (ImGui::BeginCombo(_("Card"), cardNames[m_selectedCard - 1])) {
        for (unsigned i = 0; i < 2; i++) {
            if (ImGui::Selectable(cardNames[i], m_selectedCard == i + 1)) {
                m_selectedCard = i + 1;
            }
        }
        ImGui::EndCombo();
    }

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                             ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    PCSX::SIO::McdBlock block; // The current memory card block we're looking into

    if (ImGui::BeginTable("Memory card information", 3, flags)) {
        ImGui::TableSetupColumn("Block number");
        ImGui::TableSetupColumn("Title");
        ImGui::TableSetupColumn("ID");
        ImGui::TableHeadersRow();

        for (auto i = 1; i < 16; i++) {
            g_emulator->m_sio->GetMcdBlockInfo(m_selectedCard, i, &block);

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", i);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text(block.Title);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%d", block.ID);
        }
        ImGui::EndTable();
    }

    if (m_showMemoryEditor) {
        const auto data = g_emulator->m_sio->GetMcdData(m_selectedCard);
        m_memoryEditor.DrawWindow(_("Memory Card Viewer"), data, PCSX::SIO::MCD_SIZE);
    }

    ImGui::End();
    return changed;
}
