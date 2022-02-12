/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "gui/widgets/memory_observer.h"

#include <magic_enum/include/magic_enum.hpp>

#include "imgui.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/system.h"

void PCSX::Widgets::MemoryObserver::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    uint8_t* mem_data = g_emulator->m_psxMem->g_psxM;
    uint32_t mem_size = 8 * 1024 * 1024;
    uint32_t mem_base = 0x80000000;

    if (m_address_value_pairs.empty() && ImGui::Button("First scan")) {

        for (uint32_t i = 0; i < mem_size; ++i) {
            const uint8_t mem_value = mem_data[i];
            const auto search_value = static_cast<uint8_t>(m_value);
            switch (m_scantype) {
                case ScanType::ExactValue:
                    if (mem_value == search_value) {
                        m_address_value_pairs.push_back({mem_base + i, mem_value});
                    }
                    break;
                case ScanType::BiggerThan:
                    if (mem_value < search_value) {
                        m_address_value_pairs.push_back({mem_base + i, mem_value});
                    }
                    break;
                case ScanType::SmallerThan:
                    if (mem_value > search_value) {
                        m_address_value_pairs.push_back({mem_base + i, mem_value});
                    }
                    break;
                case ScanType::Changed:
                case ScanType::Unchanged:
                case ScanType::Increased:
                case ScanType::Decreased:
                    break;
                case ScanType::UnknownInitialValue:
                    m_address_value_pairs.push_back({mem_base + i, mem_value});
                    break;
                default: ;
            }
        }
    }

    if (!m_address_value_pairs.empty() && ImGui::Button("Next scan")) {
        auto doesnt_match_criterion = [this, mem_data, mem_size, mem_base](const AddressValuePair& address_value_pair) {
            const uint32_t address = address_value_pair.address;
            const uint32_t index = address - mem_base;
            assert(index < mem_size);
            const uint8_t mem_value = mem_data[index];

            switch (m_scantype) {
                case ScanType::ExactValue:
                    return mem_value != m_value;
                case ScanType::BiggerThan:
                    return mem_value <= m_value;
                case ScanType::SmallerThan:
                    return mem_value >= m_value;
                case ScanType::Changed:
                    return mem_value == address_value_pair.scanned_value;
                case ScanType::Unchanged:
                    return mem_value != address_value_pair.scanned_value;
                case ScanType::Increased:
                    return mem_value <= address_value_pair.scanned_value;
                case ScanType::Decreased:
                    return mem_value >= address_value_pair.scanned_value;
                case ScanType::UnknownInitialValue:
                    break;
                default:
                    return true;
            }

            return true;
        };

        std::erase_if(m_address_value_pairs, doesnt_match_criterion);

        for (auto& address_value_pair : m_address_value_pairs) {
            address_value_pair.scanned_value = mem_data[address_value_pair.address - mem_base];
        }
    }

    if (!m_address_value_pairs.empty() && ImGui::Button("New scan")) {
        m_address_value_pairs.clear();
    }

    ImGui::Checkbox("Hex", &m_hex);
    ImGui::InputInt("Value", &m_value, 1, 100,
                    m_hex ? ImGuiInputTextFlags_CharsHexadecimal : ImGuiInputTextFlags_CharsDecimal);

    const auto current_scantype = magic_enum::enum_name(m_scantype);
    if (ImGui::BeginCombo(_("Scan type"), current_scantype.data())) {
        for (auto v : magic_enum::enum_values<ScanType>()) {
            bool selected = (v == m_scantype);
            auto name = magic_enum::enum_name(v);
            if (ImGui::Selectable(name.data(), selected)) {
                m_scantype = v;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    ImGui::Checkbox(_("Show memory contents"), &m_showMemoryEditor);

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                             ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    if (ImGui::BeginTable("Found values", 4, flags)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Current value");
        ImGui::TableSetupColumn("Scanned value");
        ImGui::TableSetupColumn("Access");
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(m_address_value_pairs.size());
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& address_value_pair = m_address_value_pairs[row];
                const uint32_t current_address = address_value_pair.address;

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%x", current_address);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%i", mem_data[current_address - mem_base]);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%i", address_value_pair.scanned_value);
                ImGui::TableSetColumnIndex(3);
                auto buttonName = fmt::format(_("Show in memory editor##{}"), row);
                if (ImGui::Button(buttonName.c_str())) {
                    m_showMemoryEditor = true;
                    const uint32_t editor_address = current_address - mem_base;
                    m_memoryEditor.GotoAddrAndHighlight(editor_address, editor_address + 1);
                }
            }
        }
        ImGui::EndTable();
    }

    if (m_showMemoryEditor) {
        m_memoryEditor.DrawWindow(_("Memory Viewer"), mem_data, mem_size, mem_base);
    }
}

PCSX::Widgets::MemoryObserver::MemoryObserver() {
    m_memoryEditor.OptShowDataPreview = true;
    m_memoryEditor.OptUpperCaseHex = false;
}
