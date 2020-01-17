/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "gui/widgets/ftdi.h"

#include "core/system.h"
#include "ftdi/abstract.h"
#include "gui/gui.h"

void PCSX::Widgets::FTDI::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::Button(_("Scan"))) ::PCSX::FTDI::Devices::scan();

    bool isThreadRunning = ::PCSX::FTDI::Devices::isThreadRunning();
    GUI::DButton("Start Thread", !isThreadRunning, []() { ::PCSX::FTDI::Devices::startThread(); });
    GUI::DButton("Stop Thread", isThreadRunning, []() { ::PCSX::FTDI::Devices::stopThread(); });

    unsigned count = 0;
    ::PCSX::FTDI::Devices::iterate([&count](::PCSX::FTDI::Device& d) mutable {
        count++;
        return true;
    });

    ImGui::Text((std::to_string(count) + " devices detected").c_str());
    ImGui::Separator();
    ::PCSX::FTDI::Devices::iterate([](::PCSX::FTDI::Device& d) {
        ImGui::Text("Vendor Id: %04x", d.getVendorID());
        ImGui::Text("Device Id: %04x", d.getDeviceID());
        ImGui::Text("Type: %i", d.getType());
        ImGui::Text("Serial: %s", d.getSerial().c_str());
        ImGui::Text("Description: %s", d.getDescription().c_str());
        ImGui::Text("Locked: %s", d.isLocked() ? "true" : "false");
        ImGui::Text("High Speed: %s", d.isHighSpeed() ? "true" : "false");
        ImGui::Separator();
        return true;
    });

    ImGui::End();
}
