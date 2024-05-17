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

struct Grid {
    static constexpr auto FlagsColumn = ImGuiTableColumnFlags_NoResize | ImGuiTableColumnFlags_WidthFixed;

    static constexpr auto FlagsRow = ImGuiTableRowFlags_None;

    static constexpr auto FlagsTable =
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable;

    static constexpr auto FlagsTableOuter = FlagsTable | ImGuiTableFlags_NoBordersInBody | ImGuiTableFlags_ScrollX;
    static constexpr auto FlagsTableInner = FlagsTable | ImGuiTableFlags_Borders;

    static constexpr auto WidthGeneralIndex = 22.0f;
    static constexpr auto WidthGeneralOn = 30.0f;
    static constexpr auto WidthGeneralTag = 120.0f;
    static constexpr auto WidthGeneralOff = 30.0f;
    static constexpr auto WidthGeneralMute = 45.0f;
    static constexpr auto WidthGeneralSolo = 45.0f;
    static constexpr auto WidthGeneralNoise = 70.0f;
    static constexpr auto WidthGeneralFMod = 70.0f;
    static constexpr auto WidthGeneralPlot = 150.0f;
    static constexpr auto WidthGeneral =
        WidthGeneralIndex +
        WidthGeneralTag +
        WidthGeneralOn +
        WidthGeneralOff +
        WidthGeneralMute +
        WidthGeneralSolo +
        WidthGeneralNoise +
        WidthGeneralFMod +
        WidthGeneralPlot;

    static constexpr auto WidthFrequencyActive = 70.0f;
    static constexpr auto WidthFrequencyUsed = 70.0f;
    static constexpr auto WidthFrequency =
        WidthFrequencyActive +
        WidthFrequencyUsed;

    static constexpr auto WidthPositionStart = 120.0f;
    static constexpr auto WidthPositionCurrent = 120.0f;
    static constexpr auto WidthPositionLoop = 120.0f;
    static constexpr auto WidthPosition =
        WidthPositionStart +
        WidthPositionCurrent +
        WidthPositionLoop;

    static constexpr auto WidthVolumeL = 70.0f;
    static constexpr auto WidthVolumeR = 70.0f;
    static constexpr auto WidthVolume =
        WidthVolumeL +
        WidthVolumeR;

    static constexpr auto WidthAdsrA = 70.0f;
    static constexpr auto WidthAdsrD = 70.0f;
    static constexpr auto WidthAdsrS = 70.0f;
    static constexpr auto WidthAdsrR = 70.0f;
    static constexpr auto WidthAdsr =
        WidthAdsrA +
        WidthAdsrD +
        WidthAdsrS +
        WidthAdsrR;

    static constexpr auto WidthAdsrSustainLevel = 70.0f;
    static constexpr auto WidthAdsrSustainIncrease = 70.0f;
    static constexpr auto WidthAdsrSustain =
        WidthAdsrSustainLevel +
        WidthAdsrSustainIncrease;

    static constexpr auto WidthAdsrVolumeCurrent = 70.0f;
    static constexpr auto WidthAdsrVolumeEnvelope = 80.0f;
    static constexpr auto WidthAdsrVolume =
        WidthAdsrVolumeCurrent +
        WidthAdsrVolumeEnvelope;

    static constexpr auto WidthReverbAllowed = 70.0f;
    static constexpr auto WidthReverbActive = 70.0f;
    static constexpr auto WidthReverbNumber = 70.0f;
    static constexpr auto WidthReverbOffset = 70.0f;
    static constexpr auto WidthReverbRepeat = 70.0f;
    static constexpr auto WidthReverb =
        WidthReverbAllowed +
        WidthReverbActive +
        WidthReverbNumber +
        WidthReverbOffset +
        WidthReverbRepeat;
};

void PCSX::SPU::impl::debug() {
    auto delta = std::chrono::steady_clock::now() - m_lastUpdated;
    using namespace std::chrono_literals;
    while (delta >= 50ms) {
        m_lastUpdated += 50ms;
        delta -= 50ms;
        for (unsigned ch = 0; ch < MAXCHAN; ch++) {
            if (!s_chan[ch].data.get<Chan::On>().value) {
                m_channelDebugTypes[ch][m_currentDebugSample] = EMPTY;
                m_channelDebugData[ch][m_currentDebugSample] = 0.0f;
            };
            if (s_chan[ch].data.get<Chan::IrqDone>().value) {
                m_channelDebugTypes[ch][m_currentDebugSample] = IRQ;
                m_channelDebugData[ch][m_currentDebugSample] = 0.0f;
                s_chan[ch].data.get<Chan::IrqDone>().value = 0;
                continue;
            }

            if (s_chan[ch].data.get<Chan::Mute>().value) {
                m_channelDebugTypes[ch][m_currentDebugSample] = MUTED;
            } else if (s_chan[ch].data.get<Chan::Noise>().value) {
                m_channelDebugTypes[ch][m_currentDebugSample] = NOISE;
            } else if (s_chan[ch].data.get<Chan::FMod>().value == 1) {
                m_channelDebugTypes[ch][m_currentDebugSample] = FMOD1;
            } else if (s_chan[ch].data.get<Chan::FMod>().value == 2) {
                m_channelDebugTypes[ch][m_currentDebugSample] = FMOD2;
            } else {
                m_channelDebugTypes[ch][m_currentDebugSample] = DATA;
            }

            m_channelDebugData[ch][m_currentDebugSample] =
                fabsf((float)s_chan[ch].data.get<Chan::sval>().value / 32768.0f);
        }
        if (++m_currentDebugSample == DEBUG_SAMPLES) m_currentDebugSample = 0;
    }
    if (!m_showDebug) return;
    ImGui::SetNextWindowPos(ImVec2(20, 40), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1200, 430), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(_("SPU Debug"), &m_showDebug)) {
        ImGui::End();
        return;
    }

    if (ImGui::CollapsingHeader("Channels", ImGuiTreeNodeFlags_DefaultOpen)) {
        const auto style = ImGui::GetStyle();
        const auto rowHeight = ImGui::GetFrameHeightWithSpacing();
        const auto headerHeight = ImGui::GetTextLineHeightWithSpacing();
        const auto tableHeight = rowHeight * MAXCHAN + headerHeight * 2 + 4 + style.ScrollbarSize;

        // BUG ImGui hides last column border when scrolling (off by 1px)
        if (ImGui::BeginTable("SpuChannels", 8, Grid::FlagsTableOuter, ImVec2(0, tableHeight))) {
            constexpr auto fix = 2; // BUG ImGui may screw up last column width
            constexpr auto pad = 18;
            ImGui::TableSetupColumn("General", Grid::FlagsColumn, Grid::WidthGeneral + pad * fix);
            ImGui::TableSetupColumn("Frequency", Grid::FlagsColumn, Grid::WidthFrequency + pad);
            ImGui::TableSetupColumn("Position", Grid::FlagsColumn, Grid::WidthPosition + pad);
            ImGui::TableSetupColumn("Volume", Grid::FlagsColumn, Grid::WidthVolume + pad);
            ImGui::TableSetupColumn("ADSR", Grid::FlagsColumn, Grid::WidthAdsr + pad * fix);
            ImGui::TableSetupColumn("ADSR Sustain", Grid::FlagsColumn, Grid::WidthAdsrSustain + pad);
            ImGui::TableSetupColumn("ADSR Volume", Grid::FlagsColumn, Grid::WidthAdsrVolume + pad);
            ImGui::TableSetupColumn("Reverb", Grid::FlagsColumn, Grid::WidthReverb + pad * fix);
            ImGui::TableHeadersRow();

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableGeneral", 9, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("#", Grid::FlagsColumn, Grid::WidthGeneralIndex);
                ImGui::TableSetupColumn("Tag", Grid::FlagsColumn, Grid::WidthGeneralTag);
                ImGui::TableSetupColumn("On", Grid::FlagsColumn, Grid::WidthGeneralOn);
                ImGui::TableSetupColumn("Off", Grid::FlagsColumn, Grid::WidthGeneralOff);
                ImGui::TableSetupColumn("Mute", Grid::FlagsColumn, Grid::WidthGeneralMute);
                ImGui::TableSetupColumn("Solo", Grid::FlagsColumn, Grid::WidthGeneralSolo);
                ImGui::TableSetupColumn("Noise", Grid::FlagsColumn, Grid::WidthGeneralNoise);
                ImGui::TableSetupColumn("FMod", Grid::FlagsColumn, Grid::WidthGeneralFMod);
                ImGui::TableSetupColumn("Plot", Grid::FlagsColumn, Grid::WidthGeneralPlot);

                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].data;

                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);

                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%02i", i);

                    ImGui::TableNextColumn();
                    ImGui::PushItemWidth(Grid::WidthGeneralTag);
                    const auto tagLabel = "##SpuChannelTag" + std::to_string(i);
                    const auto tagHint = "Channel " + std::to_string(i);
                    ImGui::InputTextWithHint(tagLabel.c_str(), tagHint.c_str(), m_channelTag[i], CHANNEL_TAG);
                    ImGui::PopItemWidth();

                    ImGui::TableNextColumn();
                    ImGui::BeginDisabled();
                    auto bit1 = data.get<Chan::On>().value;
                    ImGui::Checkbox("", &bit1);
                    ImGui::EndDisabled();

                    ImGui::TableNextColumn();
                    auto bit2 = data.get<Chan::Stop>().value;
                    ImGui::BeginDisabled();
                    ImGui::Checkbox("", &bit2);
                    ImGui::EndDisabled();

                    const auto ch = std::to_string(i);
                    const auto buttonSize = ImVec2(rowHeight, 0);
                    const auto buttonTint = ImGui::GetStyleColorVec4(ImGuiCol_Button);
                    auto& dataThis = s_chan[i].data;
                    auto& muteThis = dataThis.get<Chan::Mute>().value;
                    auto& soloThis = dataThis.get<Chan::Solo>().value;

                    ImGui::PushStyleColor(ImGuiCol_Button, muteThis ? ImVec4(0.6f, 0.0f, 0.0f, 1.0f) : buttonTint);
                    std::string muteLabel = "M##SpuMute" + ch;
                    ImGui::TableNextColumn();
                    const auto muteSize = ImVec2(
                        (Grid::WidthGeneralMute - buttonSize.x) * 0.5f - style.FramePadding.x * 2.0f, 0);
                    ImGui::Dummy(muteSize);
                    ImGui::SameLine();
                    if (ImGui::Button(muteLabel.c_str(), buttonSize)) {
                        muteThis = !muteThis;
                        if (muteThis) {
                            soloThis = false;
                        }
                        if (ImGui::GetIO().KeyShift) {
                            std::ranges::for_each(s_chan, s_chan + MAXCHAN, [muteThis](SPUCHAN& c) {
                                c.data.get<Chan::Mute>().value = muteThis;
                                if (muteThis) {
                                    c.data.get<Chan::Solo>().value = false;
                                }
                            });
                        }
                    }
                    ImGui::PopStyleColor();

                    ImGui::PushStyleColor(ImGuiCol_Button, soloThis ? ImVec4(0.0f, 0.6f, 0.0f, 1.0f) : buttonTint);
                    std::string soloLabel = "S##SpuSolo" + ch;
                    ImGui::TableNextColumn();
                    const auto soloSize = ImVec2(
                        (Grid::WidthGeneralSolo - buttonSize.x) * 0.5f - style.FramePadding.x * 2.0f, 0);
                    ImGui::Dummy(soloSize);
                    ImGui::SameLine();
                    if (ImGui::Button(soloLabel.c_str(), buttonSize)) {
                        soloThis = !soloThis;
                        if (soloThis) {
                            muteThis = false;
                        }
                        for (unsigned j = 0; j < MAXCHAN; j++) {
                            if (j == i) {
                                continue;
                            }
                            auto& dataOther = s_chan[j].data;
                            auto& muteOther = dataOther.get<Chan::Mute>().value;
                            auto& soloOther = dataOther.get<Chan::Solo>().value;
                            if (soloThis) {
                                // multi/single solo
                                if (ImGui::GetIO().KeyShift) {
                                    if (soloOther == false) {
                                        muteOther = true;
                                    }
                                } else {
                                    muteOther = true;
                                    soloOther = false;
                                }
                            } else {
                                // mute this to keep solo ones correct
                                if (std::ranges::any_of(s_chan, s_chan + MAXCHAN, [](const SPUCHAN& c) {
                                    return c.data.get<Chan::Solo>().value;
                                })) {
                                    muteThis = true;
                                }
                            }
                        }

                        // no more solo channels -> ensure none are muted
                        if (std::ranges::all_of(s_chan, [](const SPUCHAN& c) {
                            return c.data.get<Chan::Solo>().value == false;
                        })) {
                            std::ranges::for_each(s_chan, s_chan + MAXCHAN, [](SPUCHAN& c) {
                                c.data.get<Chan::Mute>().value = false;
                            });
                        }
                    }
                    ImGui::PopStyleColor();

                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::Noise>().value);

                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::FMod>().value);

                    ImGui::TableNextColumn();
                    constexpr auto plotSize = ImVec2(Grid::WidthGeneralPlot - pad, 0);
                    ImGui::PlotHistogram("", m_channelDebugData[i], DEBUG_SAMPLES, 0, nullptr, 0.0f, 1.0f, plotSize);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableFrequency", 2, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("Active", Grid::FlagsColumn, Grid::WidthFrequencyActive);
                ImGui::TableSetupColumn("Used", Grid::FlagsColumn, Grid::WidthFrequencyUsed);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].data;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<Chan::ActFreq>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::UsedFreq>().value);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TablePosition", 3, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("Start", Grid::FlagsColumn, Grid::WidthPositionStart);
                ImGui::TableSetupColumn("Current", Grid::FlagsColumn, Grid::WidthPositionCurrent);
                ImGui::TableSetupColumn("Loop", Grid::FlagsColumn, Grid::WidthPositionLoop);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& chan = s_chan[i];
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", static_cast<int>(chan.pStart - spuMemC));
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", static_cast<int>(chan.pCurr - spuMemC));
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", static_cast<int>(chan.pLoop - spuMemC));
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableVolume", 2, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("L", Grid::FlagsColumn, Grid::WidthVolumeL);
                ImGui::TableSetupColumn("R", Grid::FlagsColumn, Grid::WidthVolumeR);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].data;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<Chan::LeftVolume>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::RightVolume>().value);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableAdsr", 4, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("A", Grid::FlagsColumn, Grid::WidthAdsrA);
                ImGui::TableSetupColumn("D", Grid::FlagsColumn, Grid::WidthAdsrD);
                ImGui::TableSetupColumn("S", Grid::FlagsColumn, Grid::WidthAdsrS);
                ImGui::TableSetupColumn("R", Grid::FlagsColumn, Grid::WidthAdsrR);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].ADSRX;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<exAttackRate>().value ^ 0x7F);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", (data.get<exDecayRate>().value ^ 0x1F) / 4);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<exSustainRate>().value ^ 0x7F);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", (data.get<exReleaseRate>().value ^ 0x1F) / 4);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableAdsrSustain", 2, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("Level", Grid::FlagsColumn, Grid::WidthAdsrSustainLevel);
                ImGui::TableSetupColumn("Increase", Grid::FlagsColumn, Grid::WidthAdsrSustainIncrease);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].ADSRX;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<exSustainLevel>().value >> 27);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<exSustainIncrease>().value);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableAdsrVolume", 2, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("Current", Grid::FlagsColumn, Grid::WidthAdsrVolumeCurrent);
                ImGui::TableSetupColumn("Envelope", Grid::FlagsColumn, Grid::WidthAdsrVolumeEnvelope);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].ADSRX;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<exVolume>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%08X", data.get<exEnvelopeVol>().value);
                }
                ImGui::EndTable();
            }

            ImGui::TableNextColumn();
            if (ImGui::BeginTable("TableReverb", 5, Grid::FlagsTableInner)) {
                ImGui::TableSetupColumn("Allowed", Grid::FlagsColumn, Grid::WidthReverbAllowed);
                ImGui::TableSetupColumn("Active", Grid::FlagsColumn, Grid::WidthReverbActive);
                ImGui::TableSetupColumn("Number", Grid::FlagsColumn, Grid::WidthReverbNumber);
                ImGui::TableSetupColumn("Offset", Grid::FlagsColumn, Grid::WidthReverbOffset);
                ImGui::TableSetupColumn("Repeat", Grid::FlagsColumn, Grid::WidthReverbRepeat);
                ImGui::TableHeadersRow();
                for (auto i = 0u; i < MAXCHAN; ++i) {
                    const auto& data = s_chan[i].data;
                    ImGui::TableNextRow(Grid::FlagsRow, rowHeight);
                    ImGui::TableNextColumn();
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("%i", data.get<Chan::Reverb>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::RVBActive>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::RVBNum>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::RVBOffset>().value);
                    ImGui::TableNextColumn();
                    ImGui::Text("%i", data.get<Chan::RVBRepeat>().value);
                }
                ImGui::EndTable();
            }
            ImGui::EndTable();
        }
        ImGui::Text("Tip: hold 'Shift' key to group mute/solo actions.");
    }

    ImGui::BeginChild("##debugSPUleft", ImVec2(ImGui::GetContentRegionAvail().x * 0.5f, 0), true);
    ImGui::Columns(1);
    for (unsigned ch = 0; ch < MAXCHAN; ch++) {
        constexpr int widthTag = 100;
        constexpr int widthInf = 40;

        const auto tagLabel = "##Tag" + std::to_string(ch);
        const auto tagHint = "Channel " + std::to_string(ch);
        ImGui::PushItemWidth(widthTag);
        ImGui::InputTextWithHint(tagLabel.c_str(), tagHint.c_str(), m_channelTag[ch], CHANNEL_TAG);
        ImGui::PopItemWidth();

        const auto plotLabel = "##Channel" + std::to_string(ch);
        constexpr ImVec2 plotSize(-widthTag - widthInf, 0);
        ImGui::SameLine();
        ImGui::PlotHistogram(plotLabel.c_str(), m_channelDebugData[ch], DEBUG_SAMPLES, 0, nullptr, 0.0f, 1.0f, plotSize);

        /* M/S buttons (mono/solo) */

        const auto buttonSize = ImVec2(ImGui::GetTextLineHeightWithSpacing(), 0);
        const auto buttonTint = ImGui::GetStyleColorVec4(ImGuiCol_Button);
        auto& dataThis = s_chan[ch].data;
        auto& muteThis = dataThis.get<Chan::Mute>().value;
        auto& soloThis = dataThis.get<Chan::Solo>().value;

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, muteThis ? ImVec4(0.6f, 0.0f, 0.0f, 1.0f) : buttonTint);
        std::string muteLabel = "M##" + std::to_string(ch);
        if (ImGui::Button(muteLabel.c_str(), buttonSize)) {
            muteThis = !muteThis;
            if (muteThis) {
                soloThis = false;
            }
            if (ImGui::GetIO().KeyShift) {
                std::ranges::for_each(s_chan, s_chan + MAXCHAN, [muteThis](SPUCHAN& c) {
                    c.data.get<Chan::Mute>().value = muteThis;
                    if (muteThis) {
                        c.data.get<Chan::Solo>().value = false;
                    }
                });
            }
        }

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, soloThis ? ImVec4(0.0f, 0.6f, 0.0f, 1.0f) : buttonTint);
        std::string soloLabel = "S##" + std::to_string(ch);
        if (ImGui::Button(soloLabel.c_str(), buttonSize)) {
            soloThis = !soloThis;
            if (soloThis) {
                muteThis = false;
            }
            for (unsigned i = 0; i < MAXCHAN; i++) {
                if (i == ch) {
                    continue;
                }
                auto& dataOther = s_chan[i].data;
                auto& muteOther = dataOther.get<Chan::Mute>().value;
                auto& soloOther = dataOther.get<Chan::Solo>().value;
                if (soloThis) {
                    // multi/single solo
                    if (ImGui::GetIO().KeyShift) {
                        if (soloOther == false) {
                            muteOther = true;
                        }
                    } else {
                        muteOther = true;
                        soloOther = false;
                    }
                } else {
                    // mute this to keep solo ones correct
                    if (std::ranges::any_of(s_chan, s_chan + MAXCHAN, [](const SPUCHAN& c) {
                        return c.data.get<Chan::Solo>().value;
                    })) {
                        muteThis = true;
                    }
                }
            }

            // no more solo channels -> ensure none are muted
            if (std::ranges::all_of(s_chan, [](const SPUCHAN& c) {
                return c.data.get<Chan::Solo>().value == false;
            })) {
                std::ranges::for_each(s_chan, s_chan + MAXCHAN, [](SPUCHAN& c) {
                    c.data.get<Chan::Mute>().value = false;
                });
            }
        }
        ImGui::PopStyleColor(2);

        const auto infoLabel = std::to_string(ch) + "##Info" + std::to_string(ch);
        ImGui::SameLine();
        if (ImGui::RadioButton(infoLabel.c_str(), m_selectedChannel == ch)) {
            m_selectedChannel = ch;
        }
    }
    ImGui::Columns(1);
    if (ImGui::Button(_("Mute all"), ImVec2(ImGui::GetContentRegionAvail().x * 0.5f, 0))) {
        for (unsigned ch = 0; ch < MAXCHAN; ch++) {
            s_chan[ch].data.get<Chan::Mute>().value = true;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(_("Unmute all"), ImVec2(-1, 0))) {
        for (unsigned ch = 0; ch < MAXCHAN; ch++) {
            s_chan[ch].data.get<Chan::Mute>().value = false;
        }
    }
    ImGui::EndChild();
    ImGui::SameLine();
    {
        auto ch = s_chan[m_selectedChannel];
        auto ADSRX = ch.ADSRX;

        ImGui::BeginChild("##debugSPUright", ImVec2(0, 0), true);
        {
            ImGui::TextUnformatted(_("ADSR channel info"));
            ImGui::Columns(2);
            {
                ImGui::TextUnformatted(_("Attack:\nDecay:\nSustain:\nRelease:"));
                ImGui::SameLine();
                ImGui::Text("%i\n%i\n%i\n%i", ADSRX.get<exAttackRate>().value ^ 0x7f,
                            (ADSRX.get<exDecayRate>().value ^ 0x1f) / 4, ADSRX.get<exSustainRate>().value ^ 0x7f,
                            (ADSRX.get<exReleaseRate>().value ^ 0x1f) / 4);
            }
            ImGui::NextColumn();
            {
                ImGui::TextUnformatted(_("Sustain level:\nSustain inc:\nCurr adsr vol:\nRaw enveloppe"));
                ImGui::SameLine();
                ImGui::Text("%i\n%i\n%i\n%08x", ADSRX.get<exSustainLevel>().value >> 27,
                            ADSRX.get<exSustainIncrease>().value, ADSRX.get<exVolume>().value,
                            ADSRX.get<exEnvelopeVol>().value);
            }
            ImGui::Columns(1);
            ImGui::Separator();
            ImGui::TextUnformatted(_("Generic channel info"));
            ImGui::Columns(2);
            {
                ImGui::TextUnformatted(
                    _("On:\nStop:\nNoise:\nFMod:\nReverb:\nRvb active:\nRvb number:\nRvb offset:\nRvb repeat:"));
                ImGui::SameLine();
                ImGui::Text("%i\n%i\n%i\n%i\n%i\n%i\n%i\n%i\n%i", ch.data.get<Chan::On>().value,
                            ch.data.get<Chan::Stop>().value, ch.data.get<Chan::Noise>().value,
                            ch.data.get<Chan::FMod>().value, ch.data.get<Chan::Reverb>().value,
                            ch.data.get<Chan::RVBActive>().value, ch.data.get<Chan::RVBNum>().value,
                            ch.data.get<Chan::RVBOffset>().value, ch.data.get<Chan::RVBRepeat>().value);
            }
            ImGui::NextColumn();
            {
                ImGui::TextUnformatted(
                    _("Start pos:\nCurr pos:\nLoop pos:\n\nRight vol:\nLeft vol:\n\nAct freq:\nUsed freq:"));
                ImGui::SameLine();
                ImGui::Text("%li\n%li\n%li\n\n%6i  %04x\n%6i  %04x\n\n%i\n%i", ch.pStart - spuMemC, ch.pCurr - spuMemC,
                            ch.pLoop - spuMemC, ch.data.get<Chan::RightVolume>().value,
                            ch.data.get<Chan::RightVolRaw>().value, ch.data.get<Chan::LeftVolume>().value,
                            ch.data.get<Chan::LeftVolRaw>().value, ch.data.get<Chan::ActFreq>().value,
                            ch.data.get<Chan::UsedFreq>().value);
            }
            ImGui::Columns(1);
            ImGui::BeginChild("##debugSPUXA", ImVec2(ImGui::GetContentRegionAvail().x * 0.5f, 0), true);
            {
                ImGui::TextUnformatted("XA");
                ImGui::TextUnformatted(_("Freq:\nStereo:\nSamples:\nVolume:\n"));
                ImGui::SameLine();
                ImGui::Text("%i\n%i\n%i\n%5i  %5i", xapGlobal ? xapGlobal->freq : 0, xapGlobal ? xapGlobal->stereo : 0,
                            xapGlobal ? xapGlobal->nsamples : 0, iLeftXAVol, iRightXAVol);
            }
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("##debugSPUstate", ImVec2(0, 0), true);
            {
                ImGui::TextUnformatted(_("Spu states"));
                ImGui::TextUnformatted(_("Irq addr:\nCtrl:\nStat:\nSpu mem:"));
                ImGui::SameLine();
                ImGui::Text("%li\n%04x\n%04x\n%i", pSpuIrq ? -1 : pSpuIrq - spuMemC, spuCtrl, spuStat, spuAddr);
            }
            ImGui::EndChild();
        }
        ImGui::EndChild();
    }

    ImGui::End();
}
