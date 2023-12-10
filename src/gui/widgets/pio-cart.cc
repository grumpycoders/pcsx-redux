/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "gui/widgets/pio-cart.h"

#include "core/pio-cart.h"
#include "core/psxemulator.h"
#include "imgui.h"

bool PCSX::Widgets::PIOCart::draw(const char* title) {
    bool selectEXP1Dialog = false;
    bool changed = false;
    auto& settings = g_emulator->settings;

    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return false;
    } else {
        auto pio_rom = settings.get<Emulator::SettingEXP1Filepath>().string();
        ImGui::InputText(_("ROM"), const_cast<char*>(reinterpret_cast<const char*>(pio_rom.c_str())), pio_rom.length(),
                         ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        selectEXP1Dialog = ImGui::Button("...");
        ImGui::SameLine();
        if (ImGui::Button(_("Clear"))) {
            settings.get<Emulator::SettingEXP1Filepath>().value = "";
            g_emulator->m_mem->loadEXP1FromFile(g_emulator->settings.get<Emulator::SettingEXP1Filepath>().value);
            changed = true;
        }

        ImGui::TextUnformatted(_("On/Off Switch:"));
        ImGui::SameLine();
        if (ImGui::Checkbox("##ToggleSwitch", &m_switchOn)) {
            g_emulator->m_pioCart->setSwitch(m_switchOn);
        }
        ImGui::SameLine();
        ImGui::TextUnformatted(m_switchOn ? _("On") : _("Off"));

        if (ImGui::Checkbox(_("Connected"), &settings.get<Emulator::SettingPIOConnected>().value)) {
            g_emulator->m_pioCart->setLuts();
        }

        {  // Select EXP1 Dialog
            auto& exp1path = settings.get<Emulator::SettingEXP1BrowsePath>();
            if (selectEXP1Dialog) {
                if (!exp1path.empty()) {
                    m_selectEXP1Dialog.m_currentPath = exp1path.value;
                }

                m_selectEXP1Dialog.openDialog();
            }
            if (m_selectEXP1Dialog.draw()) {
                exp1path = m_selectEXP1Dialog.m_currentPath;
                std::vector<PCSX::u8string> fileToOpen = m_selectEXP1Dialog.selected();
                if (!fileToOpen.empty()) {
                    // Maybe we should check the file size here?
                    // Display a warning if the file is too big?
                    settings.get<Emulator::SettingEXP1Filepath>().value = fileToOpen[0];
                    g_emulator->m_mem->loadEXP1FromFile(
                        g_emulator->settings.get<Emulator::SettingEXP1Filepath>().value);
                    changed = true;
                }
            }
        }
        ImGui::End();
    }

    return changed;
}
