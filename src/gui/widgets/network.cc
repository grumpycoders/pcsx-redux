/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gui/widgets/network.h"

#include <magic_enum/magic_enum_all.hpp>

#include "core/gdb-server.h"
#include "core/psxemulator.h"
#include "core/sio1-server.h"
#include "core/sio1.h"
#include "core/system.h"
#include "core/web-server.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"
#include "support/imgui-helpers.h"

namespace {

ImU32 statusColor(PCSX::Network::Status status) {
    switch (status) {
        case PCSX::Network::Status::Stopped:
            return IM_COL32(128, 128, 128, 255);
        case PCSX::Network::Status::Starting:
            return IM_COL32(230, 180, 40, 255);
        case PCSX::Network::Status::Running:
            return IM_COL32(60, 200, 60, 255);
        case PCSX::Network::Status::Failed:
            return IM_COL32(220, 60, 60, 255);
    }
    return IM_COL32(128, 128, 128, 255);
}

}  // namespace

void PCSX::Widgets::Network::drawStatus(const PCSX::Network::Endpoint* endpoint) {
    // Drawn rather than glyphed, so this needs nothing from the font.
    const float radius = ImGui::GetTextLineHeight() * 0.28f;
    const ImVec2 cursor = ImGui::GetCursorScreenPos();
    const ImVec2 center(cursor.x + radius + 2.0f, cursor.y + ImGui::GetTextLineHeight() * 0.5f);
    ImGui::GetWindowDrawList()->AddCircleFilled(center, radius, statusColor(endpoint->status()));
    ImGui::Dummy(ImVec2((radius + 2.0f) * 2.0f, ImGui::GetTextLineHeight()));
    ImGui::SameLine();
}

bool PCSX::Widgets::Network::drawEndpointHeader(PCSX::Network::Endpoint* endpoint, bool enabled) {
    bool restarted = false;
    drawStatus(endpoint);
    ImGui::Text("%s", endpoint->name().data());
    ImGui::SameLine();
    ImGui::TextDisabled("(%s)", PCSX::Network::toString(endpoint->status()));

    // Restarting something that was never switched on is meaningless, and so is
    // restarting while a bind or connect is still in flight.
    const auto status = endpoint->status();
    const bool canRestart =
        enabled && ((status == PCSX::Network::Status::Running) || (status == PCSX::Network::Status::Failed));
    ImGui::SameLine();
    if (!canRestart) ImGui::BeginDisabled();
    ImGui::PushID(endpoint);
    if (ImGui::SmallButton(_("Restart"))) {
        endpoint->restart();
        restarted = true;
    }
    ImGui::PopID();
    if (!canRestart) ImGui::EndDisabled();

    // The whole point of the exercise: a failed bind used to be completely
    // silent, with the checkbox still ticked.
    const char* error = endpoint->lastError();
    if ((status == PCSX::Network::Status::Failed) && error && error[0]) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        ImGui::TextWrapped("%s", error);
        ImGui::PopStyleColor();
    }
    return restarted;
}

bool PCSX::Widgets::Network::draw(GUI* gui, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return false;
    }

    bool changed = false;
    auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();

    // -- GDB server --
    if (ImGui::CollapsingHeader(_("GDB Server"), ImGuiTreeNodeFlags_DefaultOpen)) {
        drawEndpointHeader(g_emulator->m_gdbServer.get(), debugSettings.get<Emulator::DebugSettings::GdbServer>());
        if (ImGui::Checkbox(_("Enable GDB Server"), &debugSettings.get<Emulator::DebugSettings::GdbServer>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::GdbServer>()) {
                g_emulator->m_gdbServer->start(g_system->getLoop(),
                                               debugSettings.get<Emulator::DebugSettings::GdbServerPort>());
            } else {
                g_emulator->m_gdbServer->stop();
            }
        }
        ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a gdb-server that you can
connect to with any gdb-remote compliant client.
You also need to enable the debugger.)"));
        changed |=
            ImGui::InputInt(_("GDB Server Port"), &debugSettings.get<Emulator::DebugSettings::GdbServerPort>().value);
        ImGuiHelpers::ShowHelpMarker(_(R"(A port change only takes effect on the
next restart of the server.)"));
        changed |=
            ImGui::Checkbox(_("GDB send manifest"), &debugSettings.get<Emulator::DebugSettings::GdbManifest>().value);
        ImGuiHelpers::ShowHelpMarker(_(R"(Enables sending the processor's manifest
from the gdb server. Keep this enabled, unless
you want to connect IDA to this server, as it
has a bug in its manifest parser.)"));
        changed |=
            ImGui::Checkbox(_("GDB Server Trace"), &debugSettings.get<Emulator::DebugSettings::GdbServerTrace>().value);
        ImGuiHelpers::ShowHelpMarker(_(R"(The GDB server will start tracing its
protocol into the logs, which can be helpful to debug
the gdb server system itself.)"));
        auto& currentGdbLog = debugSettings.get<Emulator::DebugSettings::GdbLogSetting>().value;
        auto currentGdbLogName = magic_enum::enum_name(currentGdbLog);
        if (ImGui::BeginCombo(_("PCSX Logs to GDB"), currentGdbLogName.data())) {
            for (auto v : magic_enum::enum_values<Emulator::DebugSettings::GdbLog>()) {
                bool selected = (v == currentGdbLog);
                auto name = magic_enum::enum_name(v);
                if (ImGui::Selectable(name.data(), selected)) {
                    currentGdbLog = v;
                    changed = true;
                }
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
    }

    // -- Web server --
    if (ImGui::CollapsingHeader(_("Web Server"), ImGuiTreeNodeFlags_DefaultOpen)) {
        drawEndpointHeader(g_emulator->m_webServer.get(), debugSettings.get<Emulator::DebugSettings::WebServer>());
        if (ImGui::Checkbox(_("Enable Web Server"), &debugSettings.get<Emulator::DebugSettings::WebServer>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::WebServer>()) {
                g_emulator->m_webServer->start(g_system->getLoop(),
                                               debugSettings.get<Emulator::DebugSettings::WebServerPort>());
            } else {
                g_emulator->m_webServer->stop();
            }
        }
        ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a web-server, that you can
query using a REST api. See the wiki for details.)"));
        changed |=
            ImGui::InputInt(_("Web Server Port"), &debugSettings.get<Emulator::DebugSettings::WebServerPort>().value);
        ImGuiHelpers::ShowHelpMarker(_(R"(A port change only takes effect on the
next restart of the server.)"));
    }

    // -- SIO1 --
    if (ImGui::CollapsingHeader(_("SIO1"), ImGuiTreeNodeFlags_DefaultOpen)) {
        drawEndpointHeader(g_emulator->m_sio1Server.get(), debugSettings.get<Emulator::DebugSettings::SIO1Server>());
        if (ImGui::Checkbox(_("Enable SIO1 Server"), &debugSettings.get<Emulator::DebugSettings::SIO1Server>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::SIO1Server>()) {
                g_emulator->m_sio1Server->start(g_system->getLoop(),
                                                debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>());
            } else {
                g_emulator->m_sio1Server->stop();
            }
        }
        ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a tcp server, that will
relay information between tcp and sio1.
See the wiki for details.)"));
        changed |= ImGui::InputInt(_("SIO1 Server Port"),
                                   &debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>().value);

        ImGui::Separator();

        drawEndpointHeader(g_emulator->m_sio1Client.get(), debugSettings.get<Emulator::DebugSettings::SIO1Client>());
        if (ImGui::Checkbox(_("Enable SIO1 Client"), &debugSettings.get<Emulator::DebugSettings::SIO1Client>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::SIO1Client>()) {
                g_emulator->m_sio1Client->start(
                    g_system->getLoop(),
                    std::string_view(debugSettings.get<Emulator::DebugSettings::SIO1ClientHost>().value),
                    debugSettings.get<Emulator::DebugSettings::SIO1ClientPort>());
            } else {
                g_emulator->m_sio1Client->stop();
            }
        }
        // This used to be flagged CharsDecimal, so a hostname could not be
        // typed into the hostname field.
        changed |= ImGui::InputText(_("SIO1 Client Host"),
                                    &debugSettings.get<Emulator::DebugSettings::SIO1ClientHost>().value);
        changed |= ImGui::InputInt(_("SIO1 Client Port"),
                                   &debugSettings.get<Emulator::DebugSettings::SIO1ClientPort>().value);

        if (ImGui::Button(_("Reset SIO"))) {
            g_emulator->m_sio1->reset();
        }

        auto& currentSIO1Mode = debugSettings.get<Emulator::DebugSettings::SIO1ModeSetting>().value;
        auto currentSIO1Name = magic_enum::enum_name(currentSIO1Mode);
        if (ImGui::BeginCombo(_("SIO1Mode"), currentSIO1Name.data())) {
            for (auto v : magic_enum::enum_values<Emulator::DebugSettings::SIO1Mode>()) {
                bool selected = (v == currentSIO1Mode);
                auto name = magic_enum::enum_name(v);
                if (ImGui::Selectable(name.data(), selected)) {
                    currentSIO1Mode = v;
                    changed = true;
                }
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
    }

    ImGui::End();
    return changed;
}
