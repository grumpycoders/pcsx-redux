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

#include "gui/widgets/kernellog.h"

#include "core/kernel.h"
#include "core/r3000a.h"
#include "imgui.h"

bool PCSX::Widgets::KernelLog::draw(R3000Acpu* cpu, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return false;
    }

    bool changed = false;

    unsigned numRows = std::max(std::max(Kernel::getA0namesSize(), Kernel::getB0namesSize()), Kernel::getC0namesSize());

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                             ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    if (ImGui::BeginTable("Kernel Calls", 4, flags)) {
        ImGui::TableSetupColumn("");
        ImGui::TableSetupColumn("A0");
        ImGui::TableSetupColumn("B0");
        ImGui::TableSetupColumn("C0");
        ImGui::TableHeadersRow();
        for (unsigned i = 0; i < numRows; i++) {
            bool v;
            const char* name;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%02X", i);
            name = Kernel::getA0name(i);
            auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
            if (name) {
                uint32_t* flags = nullptr;
                switch (i / 32) {
                    case 0:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_00_1f>().value;
                        break;
                    case 1:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_20_3f>().value;
                        break;
                    case 2:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_40_5f>().value;
                        break;
                    case 3:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_60_7f>().value;
                        break;
                    case 4:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_80_9f>().value;
                        break;
                    case 5:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_a0_bf>().value;
                        break;
                }
                ImGui::TableSetColumnIndex(1);
                std::string label = fmt::format("{}##a{}", name, i);
                changed |= ImGui::CheckboxFlags(label.c_str(), flags, 1 << (i % 32));
            }
            name = Kernel::getB0name(i);
            if (name) {
                uint32_t* flags = nullptr;
                switch (i / 32) {
                    case 0:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_00_1f>().value;
                        break;
                    case 1:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_20_3f>().value;
                        break;
                    case 2:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_40_5f>().value;
                        break;
                }
                ImGui::TableSetColumnIndex(2);
                std::string label = fmt::format("{}##b{}", name, i);
                changed |= ImGui::CheckboxFlags(label.c_str(), flags, 1 << (i % 32));
            }
            name = Kernel::getC0name(i);
            if (name) {
                uint32_t* flags = nullptr;
                switch (i / 32) {
                    case 0:
                        flags = &debugSettings.get<Emulator::DebugSettings::KernelCallC0_00_1f>().value;
                        break;
                }
                ImGui::TableSetColumnIndex(3);
                std::string label = fmt::format("{}##c{}", name, i);
                changed |= ImGui::CheckboxFlags(label.c_str(), flags, 1 << (i % 32));
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();

    return changed;
}
