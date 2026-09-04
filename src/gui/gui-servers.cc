/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#ifndef __EMSCRIPTEN__

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

bool PCSX::GUI::debugServersUI() {
    bool changed = false;
    auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();

    if (ImGui::Checkbox(_("Enable GDB Server"), &debugSettings.get<Emulator::DebugSettings::GdbServer>().value)) {
        changed = true;
        if (debugSettings.get<Emulator::DebugSettings::GdbServer>()) {
            g_emulator->m_gdbServer->startServer(g_system->getLoop(),
                                                 debugSettings.get<Emulator::DebugSettings::GdbServerPort>());
        } else {
            g_emulator->m_gdbServer->stopServer();
        }
    }
    ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a gdb-server that you can
connect to with any gdb-remote compliant client.
You also need to enable the debugger.)"));
    changed |=
        ImGui::Checkbox(_("GDB send manifest"), &debugSettings.get<Emulator::DebugSettings::GdbManifest>().value);
    ImGuiHelpers::ShowHelpMarker(_(R"(Enables sending the processor's manifest
from the gdb server. Keep this enabled, unless
you want to connect IDA to this server, as it
has a bug in its manifest parser.)"));
    auto& currentGdbLog = debugSettings.get<Emulator::DebugSettings::GdbLogSetting>().value;
    auto currentName = magic_enum::enum_name(currentGdbLog);

    if (ImGui::BeginCombo(_("PCSX Logs to GDB"), currentName.data())) {
        for (auto v : magic_enum::enum_values<Emulator::DebugSettings::GdbLog>()) {
            bool selected = (v == currentGdbLog);
            auto name = magic_enum::enum_name(v);
            if (ImGui::Selectable(name.data(), selected)) {
                currentGdbLog = v;
                changed = true;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    changed |=
        ImGui::InputInt(_("GDB Server Port"), &debugSettings.get<Emulator::DebugSettings::GdbServerPort>().value);
    changed |=
        ImGui::Checkbox(_("GDB Server Trace"), &debugSettings.get<Emulator::DebugSettings::GdbServerTrace>().value);
    ImGuiHelpers::ShowHelpMarker(_(R"(The GDB server will start tracing its
protocol into the logs, which can be helpful to debug
the gdb server system itself.)"));
    if (ImGui::Checkbox(_("Enable Web Server"), &debugSettings.get<Emulator::DebugSettings::WebServer>().value)) {
        changed = true;
        if (debugSettings.get<Emulator::DebugSettings::WebServer>()) {
            g_emulator->m_webServer->startServer(g_system->getLoop(),
                                                 debugSettings.get<Emulator::DebugSettings::WebServerPort>());
        } else {
            g_emulator->m_webServer->stopServer();
        }
    }
    ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a web-server, that you can
query using a REST api. See the wiki for details.
The debugger might be required in some cases.)"));
    changed |=
        ImGui::InputInt(_("Web Server Port"), &debugSettings.get<Emulator::DebugSettings::WebServerPort>().value);
    if (ImGui::Checkbox(_("Enable SIO1 Server"), &debugSettings.get<Emulator::DebugSettings::SIO1Server>().value)) {
        changed = true;
        if (debugSettings.get<Emulator::DebugSettings::SIO1Server>()) {
            g_emulator->m_sio1Server->startServer(g_system->getLoop(),
                                                  debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>());
        } else {
            g_emulator->m_sio1Server->stopServer();
        }
    }
    ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a tcp server, that will
relay information between tcp and sio1.
See the wiki for details.)"));
    changed |=
        ImGui::InputInt(_("SIO1 Server Port"), &debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>().value);
    if (ImGui::Checkbox(_("Enable SIO1 Client"), &debugSettings.get<Emulator::DebugSettings::SIO1Client>().value)) {
        changed = true;
        if (debugSettings.get<Emulator::DebugSettings::SIO1Client>()) {
            g_emulator->m_sio1Client->startClient(
                std::string_view(g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                     .get<Emulator::DebugSettings::SIO1ClientHost>()
                                     .value),
                g_emulator->settings.get<Emulator::SettingDebugSettings>()
                    .get<Emulator::DebugSettings::SIO1ClientPort>());
        } else {
            g_emulator->m_sio1Client->stopClient();
        }
    }
    ImGuiHelpers::ShowHelpMarker(_(R"(This will activate a tcp client, that can connect
to another PCSX-Redux server to relay information between tcp and sio1.
See the wiki for details.)"));
    changed |=
        ImGui::InputText(_("SIO1 Client Host"), &debugSettings.get<Emulator::DebugSettings::SIO1ClientHost>().value,
                         ImGuiInputTextFlags_CharsDecimal);
    changed |=
        ImGui::InputInt(_("SIO1 Client Port"), &debugSettings.get<Emulator::DebugSettings::SIO1ClientPort>().value);

    return changed;
}

bool PCSX::GUI::sio1ReconnectUI() {
    bool changed = false;
    auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();

    const bool enableReconnect = debugSettings.get<Emulator::DebugSettings::SIO1Client>() &&
                                 !g_emulator->m_sio1->connecting() && g_emulator->m_sio1->fifoError();

    if (!enableReconnect) {
        ImGui::BeginDisabled();
    }

    if (ImGui::Button(_("Reconnect"))) {
        g_emulator->m_sio1Client->reconnect(
            std::string_view(g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                 .get<Emulator::DebugSettings::SIO1ClientHost>()
                                 .value),
            g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::SIO1ClientPort>());
    }

    if (!enableReconnect) {
        ImGui::EndDisabled();
    }

    return changed;
}

#endif  // __EMSCRIPTEN__
