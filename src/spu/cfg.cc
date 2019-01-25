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

#include "imgui.h"

#include "spu/interface.h"

static void ShowHelpMarker(const char *desc) {
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

bool PCSX::SPU::impl::configure() {
    if (!m_showCfg) return false;
    ImGui::SetNextWindowPos(ImVec2(70, 90), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(550, 220), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("SPU configuration", &m_showCfg)) {
        ImGui::End();
        return false;
    }
    bool changed = false;

    changed |= ImGui::Checkbox("Enable streaming", &settings.get<Streaming>().value);
    ShowHelpMarker(R"(Uncheck this to mute the streaming channel
from the main CPU to the SPU. This includes
XA audio and audio tracks.)");
    static const char *volumeValues[] = {"Low", "Medium", "Loud", "Loudest"};
    changed |= ImGui::Combo("Volume", &settings.get<Volume>().value, volumeValues, IM_ARRAYSIZE(volumeValues));
    changed |= ImGui::Checkbox("Change streaming pitch", &settings.get<StreamingPitch>().value);
    ShowHelpMarker(R"(Attempts to make the CPU-to-SPU audio stream
in sync, by changing its pitch. Consumes more CPU.)");
    changed |= ImGui::Checkbox("Pause SPU waiting for CPU IRQ", &settings.get<SPUIRQWait>().value);
    ShowHelpMarker(R"(Suspends the SPU processing during an IRQ, waiting
for the main CPU to acknowledge it. Fixes issues
with some games, but slows SPU processing.)");
    static const char *reverbValues[] = {"None - fastest", "Simple - only handles the most common effects",
                                         "Accurate - best quality, but slower"};
    changed |= ImGui::Combo("Reverb", &settings.get<Reverb>().value, reverbValues, IM_ARRAYSIZE(reverbValues));
    static const char *interpolationValues[] = {"None - fastest", "Simple interpolation",
                                                "Gaussian interpolation - good quality",
                                                "Cubic interpolation - better treble"};
    changed |=
        ImGui::Combo("Interpolation", &settings.get<Interpolation>().value, interpolationValues, IM_ARRAYSIZE(interpolationValues));
    changed |= ImGui::Checkbox("Mono", &settings.get<Mono>().value);
    ShowHelpMarker("Downmixes stereo to mono.");
    changed |= ImGui::Checkbox("Decoded buffers IRQ", &settings.get<DBufIRQ>().value);
    ShowHelpMarker("Generates IRQs when buffers are decoded.");

    ImGui::End();
    return changed;
}
