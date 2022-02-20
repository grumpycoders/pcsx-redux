/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#ifdef MEMORY_OBSERVER_X86
#include <xbyak_util.h>
#endif

#include <magic_enum/include/magic_enum.hpp>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/system.h"

PCSX::Widgets::MemoryObserver::MemoryObserver() {
#ifdef MEMORY_OBSERVER_X86
    const auto cpu = Xbyak::util::Cpu();
    m_useSIMD = cpu.has(Xbyak::util::Cpu::tAVX2);
#endif
}

void PCSX::Widgets::MemoryObserver::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("SearchTabBar")) {
        const uint8_t* memData = g_emulator->m_psxMem->g_psxM;
        const uint32_t memSize = 1024 * 1024 * (g_emulator->settings.get<PCSX::Emulator::Setting8MB>() ? 8 : 2);
        constexpr uint32_t memBase = 0x80000000;

        static constexpr ImGuiTableFlags tableFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                                      ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                                      ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;

        if (ImGui::BeginTabItem("Delta-over-time search")) {
            const auto stride = static_cast<uint8_t>(m_scanAlignment);

            if (m_addressValuePairs.empty() && ImGui::Button("First scan")) {
                int memValue = 0;

                for (uint32_t i = 0; i < memSize; ++i) {
                    if (i != 0 && i % stride == 0) {
                        switch (m_scanType) {
                            case ScanType::ExactValue:
                                if (memValue == m_value) {
                                    m_addressValuePairs.push_back({memBase + i - stride, memValue});
                                }
                                break;
                            case ScanType::BiggerThan:
                                if (memValue > m_value) {
                                    m_addressValuePairs.push_back({memBase + i - stride, memValue});
                                }
                                break;
                            case ScanType::SmallerThan:
                                if (memValue < m_value) {
                                    m_addressValuePairs.push_back({memBase + i - stride, memValue});
                                }
                                break;
                            case ScanType::Changed:
                            case ScanType::Unchanged:
                            case ScanType::Increased:
                            case ScanType::Decreased:
                                break;
                            case ScanType::UnknownInitialValue:
                                m_addressValuePairs.push_back({memBase + i - stride, memValue});
                                break;
                        }

                        memValue = 0;
                    }

                    const uint8_t currentByte = memData[i];
                    const uint8_t leftShift = 8 * (stride - 1 - i % stride);
                    const uint32_t mask = 0xffffffff ^ (0xff << leftShift);
                    const int byteToWrite = currentByte << leftShift;
                    memValue = (memValue & mask) | byteToWrite;
                }
            }

            if (!m_addressValuePairs.empty() && ImGui::Button("Next scan")) {
                auto doesntMatchCriterion = [this, memData, memSize, memBase,
                                             stride](const AddressValuePair& addressValuePair) {
                    const uint32_t address = addressValuePair.address;
                    const int memValue = getMemValue(address, memData, memSize, memBase, stride);

                    switch (m_scanType) {
                        case ScanType::ExactValue:
                            return memValue != m_value;
                        case ScanType::BiggerThan:
                            return memValue <= m_value;
                        case ScanType::SmallerThan:
                            return memValue >= m_value;
                        case ScanType::Changed:
                            return memValue == addressValuePair.scannedValue;
                        case ScanType::Unchanged:
                            return memValue != addressValuePair.scannedValue;
                        case ScanType::Increased:
                            return memValue <= addressValuePair.scannedValue;
                        case ScanType::Decreased:
                            return memValue >= addressValuePair.scannedValue;
                        case ScanType::UnknownInitialValue:
                            return true;
                    }

                    return true;
                };

                std::erase_if(m_addressValuePairs, doesntMatchCriterion);

                if (m_addressValuePairs.empty()) {
                    m_scanType = ScanType::ExactValue;
                } else {
                    for (auto& addressValuePair : m_addressValuePairs) {
                        addressValuePair.scannedValue =
                            getMemValue(addressValuePair.address, memData, memSize, memBase, stride);
                    }
                }
            }

            if (!m_addressValuePairs.empty() && ImGui::Button("New scan")) {
                m_addressValuePairs.clear();
                m_scanType = ScanType::ExactValue;
            }

            ImGui::Checkbox("Hex", &m_hex);
            ImGui::InputInt("Value", &m_value, 1, 100,
                            m_hex ? ImGuiInputTextFlags_CharsHexadecimal : ImGuiInputTextFlags_CharsDecimal);

            const auto currentScanAlignment = magic_enum::enum_name(m_scanAlignment);
            if (ImGui::BeginCombo(_("Scan alignment"), currentScanAlignment.data())) {
                for (auto v : magic_enum::enum_values<ScanAlignment>()) {
                    bool selected = (v == m_scanAlignment);
                    auto name = magic_enum::enum_name(v);
                    if (ImGui::Selectable(name.data(), selected)) {
                        m_scanAlignment = v;
                    }
                    if (selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }

            const auto currentScanType = magic_enum::enum_name(m_scanType);
            if (ImGui::BeginCombo(_("Scan type"), currentScanType.data())) {
                for (auto v : magic_enum::enum_values<ScanType>()) {
                    bool selected = (v == m_scanType);
                    auto name = magic_enum::enum_name(v);
                    if (ImGui::Selectable(name.data(), selected)) {
                        m_scanType = v;
                    }
                    if (selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }

            if (ImGui::BeginTable("Found values", 4, tableFlags)) {
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Current value");
                ImGui::TableSetupColumn("Scanned value");
                ImGui::TableSetupColumn("Access");
                ImGui::TableHeadersRow();

                const auto valueDisplayFormat = m_hex ? "%x" : "%i";

                ImGuiListClipper clipper;
                clipper.Begin(m_addressValuePairs.size());
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto& addressValuePair = m_addressValuePairs[row];
                        const uint32_t currentAddress = addressValuePair.address;

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%x", currentAddress);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text(valueDisplayFormat, getMemValue(currentAddress, memData, memSize, memBase, stride));
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text(valueDisplayFormat, addressValuePair.scannedValue);
                        ImGui::TableSetColumnIndex(3);
                        auto buttonName = fmt::format(_("Show in memory editor##{}"), row);
                        if (ImGui::Button(buttonName.c_str())) {
                            const uint32_t editorAddress = currentAddress - memBase;
                            g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{editorAddress, stride});
                        }
                    }
                }
                ImGui::EndTable();
            }

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem(_("Pattern search"))) {
            if (m_useSIMD) {
                ImGui::Text(_("Sequence size: "));
                ImGui::SameLine();
                ImGui::RadioButton(_("8 bytes (fast)"), &m_sequenceSize, 8);
                ImGui::SameLine();
                ImGui::RadioButton(_("16 bytes (fast)"), &m_sequenceSize, 16);
                ImGui::SameLine();
                ImGui::RadioButton(_("Arbitrary"), &m_sequenceSize, 255);
            }

            ImGui::InputText(_("Sequence"), m_sequence, m_sequenceSize + 1);

            ImGui::InputInt(_("Step"), &m_step);

            if (ImGui::Button(_("Search"))) {
                if (m_useSIMD && m_sequenceSize == 8) {
                    simd_populateAddressList<8>(memData, memBase, memSize);
                } else if (m_useSIMD && m_sequenceSize == 16) {
                    simd_populateAddressList<16>(memData, memBase, memSize);
                } else {
                    populateAddressList(memData, memBase, memSize);
                }
            }

            if (ImGui::BeginTable("Found values", 2, tableFlags)) {
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Current value");
                ImGui::TableSetupColumn("Access");
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(m_addresses.size());
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto& currentAddress = m_addresses[row];

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%x", currentAddress);
                        ImGui::TableSetColumnIndex(1);
                        auto buttonName = fmt::format(_("Show in memory editor##{}"), row);
                        if (ImGui::Button(buttonName.c_str())) {
                            const uint32_t editorAddress = currentAddress - memBase;
                            g_system->m_eventBus->signal(
                                PCSX::Events::GUI::JumpToMemory{editorAddress, static_cast<unsigned>(m_sequenceSize)});
                        }
                    }
                }
                ImGui::EndTable();
            }

            ImGui::EndTabItem();
        }

        ImGui::TreePop();
    }

    ImGui::End();
}

int PCSX::Widgets::MemoryObserver::getMemValue(uint32_t absoluteAddress, const uint8_t* memData, uint32_t memSize,
                                               uint32_t memBase, uint8_t stride) {
    int memValue = 0;
    const uint32_t relativeAddress = absoluteAddress - memBase;
    assert(relativeAddress < memSize);
    for (uint32_t i = relativeAddress; i < relativeAddress + stride; ++i) {
        const uint8_t currentByte = memData[i];
        const uint8_t leftShift = 8 * (stride - 1 - i % stride);
        const uint32_t mask = 0xffffffff ^ (0xff << leftShift);
        const int byteToWrite = currentByte << leftShift;
        memValue = (memValue & mask) | byteToWrite;
    }
    return memValue;
}

#ifdef MEMORY_OBSERVER_X86
// Check if all bytes in a 256-bit vector are equal
// Broadcasts byte 0 of the vector to 256 bits, then xors the result with the starting vector
// If the resulting vector is 0, then all bytes in the 256-bit vector are equal
bool PCSX::Widgets::MemoryObserver::all_equal(__m256i vec) {
    const __m128i vec128 = _mm256_castsi256_si128(vec);
    const __m256i broadcasted = _mm256_broadcastb_epi8(vec128);
    const __m256i res = _mm256_xor_epi32(vec, broadcasted);

    // Check if the vector after xoring is 0
    return _mm256_testz_si256(res, res) != 0;
}
#endif // MEMORY_OBSERVER_X86

std::vector<uint8_t> PCSX::Widgets::MemoryObserver::getShuffleResultsFor(const std::vector<uint8_t>& buffer) {
    const size_t bufferSize = buffer.size();

    auto results = std::vector<uint8_t>(bufferSize * bufferSize);

    auto shuffledBuffer = buffer;

    for (auto i = 0u; i < bufferSize; ++i) {
        std::shift_left(shuffledBuffer.begin(), shuffledBuffer.end(), 1);

        for (auto j = 0u; j < bufferSize; ++j) {
            results[i * bufferSize + j] = (shuffledBuffer[j] == buffer[j]);
        }
    }

    return results;
}

bool PCSX::Widgets::MemoryObserver::matchesPattern(const std::vector<uint8_t>& buffer,
                                                   const std::vector<uint8_t>& patternShuffleResults) {
    const size_t bufferSize = buffer.size();

    auto shuffledBuffer = buffer;

    for (auto i = 0u; i < bufferSize; ++i) {
        std::shift_left(shuffledBuffer.begin(), shuffledBuffer.end(), 1);

        for (auto j = 0u; j < bufferSize; ++j) {
            if (patternShuffleResults[i * bufferSize + j] != (shuffledBuffer[j] == buffer[j])) {
                return false;
            }
        }
    }

    return true;
}

void PCSX::Widgets::MemoryObserver::populateAddressList(const uint8_t* memData, uint32_t memBase, uint32_t memSize) {
    const auto sequenceSize = strlen(m_sequence);
    auto buffer = std::vector<uint8_t>(m_sequence, m_sequence + sequenceSize);
    const auto patternShuffleResults = getShuffleResultsFor(buffer);

    m_addresses.clear();
    const auto step = m_step;
    for (auto i = 0; i + sequenceSize < memSize; i += step) {
        std::copy_n(memData + i, sequenceSize, buffer.data());

        if (matchesPattern(buffer, patternShuffleResults)) {
            m_addresses.push_back(memBase + i);
        }
    }
}
