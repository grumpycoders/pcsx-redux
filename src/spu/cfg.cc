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

#include "core/system.h"
#include "imgui.h"
#include "spu/interface.h"
#include "support/imgui-helpers.h"

bool PCSX::SPU::impl::configure() {
    ImGui::SetNextWindowPos(ImVec2(70, 90), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(550, 220), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(_("SPU configuration"), &m_showCfg)) {
        ImGui::End();
        return false;
    }
    bool changed = false;
    bool deviceChanged = false;
    auto backends = m_audioOut.getBackends();
    auto devices = m_audioOut.getDevices();

    std::string currentBackend = settings.get<Backend>();
    std::string currentDevice = settings.get<Device>();
    if (ImGui::BeginCombo(_("Backend"), currentBackend.c_str())) {
        for (auto &b : backends) {
            if (ImGui::Selectable(b.c_str(), currentBackend == b)) {
                settings.get<Backend>() = b;
                deviceChanged = true;
            }
        }
        ImGui::EndCombo();
    }
    if (ImGui::BeginCombo(_("Device"), currentDevice.c_str())) {
        for (auto &d : devices) {
            if (ImGui::Selectable(d.c_str(), currentDevice == d)) {
                settings.get<Device>() = d;
                deviceChanged = true;
            }
        }
        ImGui::EndCombo();
    }
    deviceChanged |= ImGui::Checkbox(_("Use Null Sync"), &settings.get<NullSync>().value);
    ImGuiHelpers::ShowHelpMarker(_(R"(More precise CPU-SPU synchronization,
at the cost of extra power required.)"));
    if (deviceChanged) {
        m_audioOut.reinit();
    }
    changed = deviceChanged;

    changed |= ImGui::Checkbox(_("Muted"), &settings.get<Mute>().value);
    changed |= ImGui::Checkbox(_("Enable streaming"), &settings.get<Streaming>().value);
    ImGuiHelpers::ShowHelpMarker(_(R"(Uncheck this to mute the streaming channel
from the main CPU to the SPU. This includes
XA audio and audio tracks.)"));
    const char *volumeValues[] = {_("Low"), _("Medium"), _("Loud"), _("Loudest")};
    changed |= ImGui::Combo(_("Volume"), &settings.get<Volume>().value, volumeValues, IM_ARRAYSIZE(volumeValues));
    ImGuiHelpers::ShowHelpMarker(_(R"(Attempts to make the CPU-to-SPU audio stream
in sync, by changing its pitch. Consumes more CPU.)"));
    changed |= ImGui::Checkbox(_("Pause SPU waiting for CPU IRQ"), &settings.get<SPUIRQWait>().value);
    ImGuiHelpers::ShowHelpMarker(_(R"(Suspends the SPU processing during an IRQ, waiting
for the main CPU to acknowledge it. Fixes issues
with some games, but slows SPU processing.)"));
    const char *reverbValues[] = {_("None - fastest"), _("Simple - only handles the most common effects"),
                                  _("Accurate - best quality, but slower")};
    changed |= ImGui::Combo(_("Reverb"), &settings.get<Reverb>().value, reverbValues, IM_ARRAYSIZE(reverbValues));
    const char *interpolationValues[] = {_("None - fastest"), _("Simple interpolation"),
                                         _("Gaussian interpolation - good quality"),
                                         _("Cubic interpolation - better treble")};
    changed |= ImGui::Combo(_("Interpolation"), &settings.get<Interpolation>().value, interpolationValues,
                            IM_ARRAYSIZE(interpolationValues));
    changed |= ImGui::Checkbox(_("Mono"), &settings.get<Mono>().value);
    ImGuiHelpers::ShowHelpMarker(_("Downmixes stereo to mono."));
    changed |= ImGui::Checkbox(_("Capture/decode buffer IRQ"), &settings.get<DBufIRQ>().value);
    ImGuiHelpers::ShowHelpMarker(
        _("Activates SPU IRQs based on writes to the decode/capture buffer. This option is necessary for some games."));

    ImGui::End();
    return changed;
}
