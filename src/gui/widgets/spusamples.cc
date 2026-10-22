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

#include "gui/widgets/spusamples.h"

#include <algorithm>

#include "core/spu.h"
#include "core/system.h"
#include "imgui.h"
#include "implot/implot.h"
#include "spu/adpcm.h"

namespace {

// ADPCM block header, byte 1.
constexpr uint8_t c_flagLoopEnd = 1;
constexpr uint8_t c_flagRepeat = 2;
constexpr uint8_t c_flagLoopStart = 4;
constexpr uint32_t c_blockSize = 16;

}  // namespace

PCSX::Widgets::SPUSamples::Sample PCSX::Widgets::SPUSamples::walk(const uint8_t* spuRam, uint32_t start) {
    Sample sample;
    sample.start = start;
    uint32_t addr = start & ~(c_blockSize - 1);
    while (true) {
        if (addr >= SPUInterface::c_spuRamSize) {
            sample.truncated = true;
            sample.end = SPUInterface::c_spuRamSize;
            break;
        }
        const uint8_t flags = spuRam[addr + 1];
        if (flags & c_flagLoopStart) {
            sample.loop = addr;
            sample.hasLoop = true;
        }
        addr += c_blockSize;
        if (flags & c_flagLoopEnd) {
            sample.end = addr;
            sample.repeats = flags & c_flagRepeat;
            break;
        }
    }
    return sample;
}

void PCSX::Widgets::SPUSamples::decode(const uint8_t* spuRam, const Sample& sample, std::vector<float>& out) {
    out.clear();
    // decodeBlock reads the block in place without writing it, but takes a mutable pointer.
    uint8_t* ram = const_cast<uint8_t*>(spuRam);
    SPU::AdpcmDecoder decoder;
    decoder.reset();
    for (uint32_t addr = sample.start; addr + c_blockSize <= sample.end; addr += c_blockSize) {
        decoder.decodeBlock(ram + addr);
        while (!decoder.bufferExhausted()) out.push_back(float(decoder.takeSample()));
    }
}

void PCSX::Widgets::SPUSamples::rebuild(PCSX::SPULogger* logger, const uint8_t* spuRam) {
    const uint64_t seen = logger->seen();
    const size_t count = logger->size();
    // A clear restarts the count; anything else is new entries at the tail of the ring.
    if (m_lastSeen == ~uint64_t(0) || logger->clears() != m_lastClears) {
        m_samples.clear();
        m_lastSeen = 0;
        m_lastClears = logger->clears();
    }
    const size_t fresh = size_t(std::min<uint64_t>(seen - m_lastSeen, count));
    for (size_t i = count - fresh; i < count; i++) {
        const auto& ev = (*logger)[i];
        if (ev.kind != PCSX::SPULogger::Kind::KeyOn) continue;
        auto& s = m_samples[ev.address];
        s.keyOns++;
        if (ev.voice < 32) s.voiceMask |= 1u << ev.voice;
    }
    m_lastSeen = seen;

    // Sound RAM may have been rewritten under any of them, so every sample is walked again.
    for (auto& [start, s] : m_samples) {
        const uint32_t keyOns = s.keyOns;
        const uint32_t voiceMask = s.voiceMask;
        s = walk(spuRam, start);
        s.keyOns = keyOns;
        s.voiceMask = voiceMask;
    }

    if (m_selected) {
        auto it = m_samples.find(m_selectedStart);
        if (it == m_samples.end()) {
            m_selected = false;
            m_waveform.clear();
        } else {
            decode(spuRam, it->second, m_waveform);
        }
    }
}

void PCSX::Widgets::SPUSamples::draw(PCSX::SPULogger* logger, const uint8_t* spuRam, const char* title) {
    ImGui::SetNextWindowSize(ImVec2(640, 640), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (!spuRam) {
        ImGui::TextUnformatted(_("The SPU is not initialized."));
        ImGui::End();
        return;
    }

    bool refresh = ImGui::Button(_("Refresh"));
    ImGui::SameLine();
    ImGui::Checkbox(_("Auto refresh"), &m_autoRefresh);
    if (refresh || (m_autoRefresh && (logger->seen() != m_lastSeen || logger->clears() != m_lastClears))) {
        rebuild(logger, spuRam);
    }

    if (!logger->enabled()) {
        ImGui::TextWrapped("%s", _("Sample starts come from key on events. Enable the SPU logger to collect them."));
    }
    ImGui::TextUnformatted(fmt::format(f_("{} samples"), m_samples.size()).c_str());

    const float tableHeight = ImGui::GetContentRegionAvail().y * 0.4f;
    if (ImGui::BeginTable(
            "SPUSamples", 6,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
            ImVec2(0, tableHeight))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(_("Start"));
        ImGui::TableSetupColumn(_("End"));
        ImGui::TableSetupColumn(_("Samples"));
        ImGui::TableSetupColumn(_("Loop"));
        ImGui::TableSetupColumn(_("Key ons"));
        ImGui::TableSetupColumn(_("Voices"));
        ImGui::TableHeadersRow();

        for (auto& [start, s] : m_samples) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const bool isSelected = m_selected && m_selectedStart == start;
            if (ImGui::Selectable(fmt::format("{:05x}", start).c_str(), isSelected,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                m_selected = true;
                m_selectedStart = start;
                decode(spuRam, s, m_waveform);
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(fmt::format("{:05x}{}", s.end, s.truncated ? "+" : "").c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(fmt::format("{}", (s.end - start) / c_blockSize * 28).c_str());
            ImGui::TableSetColumnIndex(3);
            if (s.repeats && s.hasLoop) {
                ImGui::TextUnformatted(fmt::format("{:05x}", s.loop).c_str());
            } else if (s.repeats) {
                ImGui::TextUnformatted(_("repeat"));
            } else {
                ImGui::TextUnformatted(_("one shot"));
            }
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(fmt::format("{}", s.keyOns).c_str());
            ImGui::TableSetColumnIndex(5);
            std::string voices;
            for (unsigned v = 0; v < 24; v++) {
                if (!(s.voiceMask & (1u << v))) continue;
                if (!voices.empty()) voices += ' ';
                voices += fmt::format("{}", v);
            }
            ImGui::TextUnformatted(voices.c_str());
        }
        ImGui::EndTable();
    }

    if (m_selected && !m_waveform.empty()) {
        auto it = m_samples.find(m_selectedStart);
        if (ImPlot::BeginPlot("##SPUWaveform", ImVec2(-1, -1))) {
            ImPlot::SetupAxes(_("Sample"), nullptr);
            ImPlot::SetupAxisLimits(ImAxis_Y1, -32768, 32767);
            ImPlot::PlotLine(fmt::format("{:05x}", m_selectedStart).c_str(), m_waveform.data(), int(m_waveform.size()));
            if (it != m_samples.end() && it->second.repeats && it->second.hasLoop) {
                const double loopAt = double((it->second.loop - it->second.start) / c_blockSize * 28);
                ImPlot::PlotInfLines(_("Loop"), &loopAt, 1);
            }
            ImPlot::EndPlot();
        }
    }

    ImGui::End();
}
