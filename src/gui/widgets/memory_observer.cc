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
#include "core/debug.h"
#include "imgui.h"
#include "imgui_stdlib.h"

PCSX::Widgets::MemoryObserver::MemoryObserver(bool& show) : m_show(show) {
#ifdef MEMORY_OBSERVER_X86
    const auto cpu = Xbyak::util::Cpu();
    m_useSIMD = cpu.has(Xbyak::util::Cpu::tAVX2);
#endif
}

const void* PCSX::Widgets::MemoryObserver::memmem(const void* haystack_, size_t n, const void* needle_, size_t m) {
    const uint8_t* haystack = reinterpret_cast<const uint8_t*>(haystack_);
    const uint8_t* needle = reinterpret_cast<const uint8_t*>(needle_);

    if ((m > n) || (m == 0) || (n == 0)) return nullptr;
    // The algo doesn't like it when the needle is too small.
    if (m == 1) return memchr(haystack, needle[0], n);

    // http://www-igm.univ-mlv.fr/~lecroq/string/node13.html#SECTION00130
    // Preprocessing
    size_t k = 1, l = 2;
    if (needle[0] == needle[1]) {
        k = 2;
        l = 1;
    }
    // Searching
    size_t j = 0;
    while (j <= (n - m)) {
        if (needle[1] != haystack[j + 1]) {
            j += k;
        } else {
            if ((memcmp(needle + 2, haystack + j + 2, m - 2) == 0) && (needle[0] == haystack[j])) {
                return static_cast<const void*>(haystack + j);
            }
            j += l;
        }
    }
    return nullptr;
}

void PCSX::Widgets::MemoryObserver::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("SearchTabBar")) {
        const uint8_t* const memData = g_emulator->m_mem->m_psxM;
        const uint32_t memSize = 1024 * 1024 * (g_emulator->settings.get<PCSX::Emulator::Setting8MB>() ? 8 : 2);
        constexpr uint32_t memBase = 0x80000000;

        static constexpr ImGuiTableFlags tableFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                                      ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                                      ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;

        if (ImGui::BeginTabItem(_("Plain search"))) {
            bool gotEnter = ImGui::InputText(_("Pattern"), &m_plainSearchString, ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::Checkbox(_("Hex"), &m_plainHex);
            auto needleSize = 0;
            std::string needle;
            bool valid = true;
            if (m_plainHex) {
                char n = 0;
                bool gotOne = false;
                auto maybePushOne = [&]() {
                    if (gotOne) {
                        needle += n;
                        gotOne = false;
                        needleSize++;
                        n = 0;
                    } else {
                        gotOne = true;
                    }
                };
                for (auto c : m_plainSearchString) {
                    if (c >= '0' && c <= '9') {
                        n <<= 4;
                        n |= c - '0';
                        maybePushOne();
                    } else if (c >= 'a' && c <= 'f') {
                        n <<= 4;
                        n |= c - 'a' + 10;
                        maybePushOne();
                    } else if (c >= 'A' && c <= 'F') {
                        n <<= 4;
                        n |= c - 'A' + 10;
                        maybePushOne();
                    } else if (c == ' ') {
                        if (gotOne) {
                            needle += n;
                            gotOne = false;
                            needleSize++;
                            n = 0;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (gotOne) {
                    needle += n;
                    needleSize++;
                }
            } else {
                needleSize = m_plainSearchString.size();
                needle = m_plainSearchString;
            }
            if (!valid) {
                ImGui::BeginDisabled();
            }
            if (ImGui::Button(_("Search")) || (gotEnter && valid)) {
                auto ptr = memData;
                m_plainAddresses.clear();
                while (true) {
                    auto found = reinterpret_cast<const uint8_t*>(
                        memmem(ptr, memData + memSize - ptr, needle.c_str(), needleSize));
                    if (found) {
                        m_plainAddresses.push_back(memBase + static_cast<uint32_t>(found - memData));
                        ptr = reinterpret_cast<const uint8_t*>(found) + 1;
                    } else {
                        break;
                    }
                }
            }
            if (!valid) {
                ImGui::EndDisabled();
            }
            if (ImGui::BeginTable(_("Found values"), 2, tableFlags)) {
                ImGui::TableSetupColumn(_("Address"));
                ImGui::TableSetupColumn(_("Access"));
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(m_plainAddresses.size());
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto& currentAddress = m_plainAddresses[row];

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%x", currentAddress);
                        ImGui::TableSetColumnIndex(1);
                        auto buttonName = fmt::format(f_("Show in memory editor##{}"), row);
                        if (ImGui::Button(buttonName.c_str())) {
                            const uint32_t editorAddress = currentAddress - memBase;
                            g_system->m_eventBus->signal(
                                PCSX::Events::GUI::JumpToMemory{editorAddress, static_cast<unsigned>(needleSize)});
                        }
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem(_("Delta-over-time search"))) {
            const auto stride = getStrideFromValueType(m_scanValueType);

            if (m_addressValuePairs.empty() && ImGui::Button(_("First scan"))) {
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
                    const uint8_t leftShift = 8 * (i % stride);
                    const uint32_t mask = 0xffffffff ^ (0xff << leftShift);
                    const int byteToWrite = currentByte << leftShift;
                    memValue = (memValue & mask) | byteToWrite;
                    memValue = getValueAsSelectedType(memValue);
                }
            }

            if (!m_addressValuePairs.empty() && ImGui::Button(_("Next scan"))) {
                auto doesntMatchCriterion = [this, memData, memSize, stride](const AddressValuePair& addressValuePair) {
                    const uint32_t address = addressValuePair.address;
                    const int memValue = getValueAsSelectedType(getMemValue(address, memData, memSize, memBase, stride));

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
                            getValueAsSelectedType(getMemValue(addressValuePair.address, memData, memSize, memBase, stride));
                    }
                }
            }

            if (!m_addressValuePairs.empty() && ImGui::Button(_("New scan"))) {
                m_addressValuePairs.clear();
                m_scanType = ScanType::ExactValue;
            }

            ImGui::Checkbox(_("Hex"), &m_hex);
            ImGui::InputInt(_("Value"), &m_value, 1, 100,
                            m_hex ? ImGuiInputTextFlags_CharsHexadecimal : ImGuiInputTextFlags_CharsDecimal);
            m_value = getValueAsSelectedType(m_value);

            const auto currentScanValueType = magic_enum::enum_name(m_scanValueType);
            if (ImGui::BeginCombo(_("Value type"), currentScanValueType.data())) {
                for (auto v : magic_enum::enum_values<ScanValueType>()) {
                    bool selected = (v == m_scanValueType);
                    auto name = magic_enum::enum_name(v);
                    if (ImGui::Selectable(name.data(), selected)) {
                        m_scanValueType = v;
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

            if (!m_hex && stride > 1) {
                ImGui::Checkbox(_("Display as fixed-point values"), &m_fixedPoint);
            }

            if (ImGui::BeginTable(_("Found values"), 6, tableFlags)) {
                ImGui::TableSetupColumn(_("Address"));
                ImGui::TableSetupColumn(_("Current value"));
                ImGui::TableSetupColumn(_("Scanned value"));
                ImGui::TableSetupColumn(_("Access"));
                ImGui::TableSetupColumn(_("Read breakpoint"));
                ImGui::TableSetupColumn(_("Write breakpoint"));
                ImGui::TableHeadersRow();

                const auto valueDisplayFormat = m_hex ? "%x" : (m_fixedPoint && stride > 1) ? "%i.%i" : "%i";

                ImGuiListClipper clipper;
                clipper.Begin(m_addressValuePairs.size());
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto& addressValuePair = m_addressValuePairs[row];
                        const uint32_t currentAddress = addressValuePair.address;
                        const auto memValue =
                            getValueAsSelectedType(getMemValue(currentAddress, memData, memSize, memBase, stride));
                        const auto scannedValue = addressValuePair.scannedValue;
                        const bool displayAsFixedPoint = !m_hex && m_fixedPoint && stride > 1;

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%x", currentAddress);
                        ImGui::TableSetColumnIndex(1);
                        if (displayAsFixedPoint) {
                            ImGui::Text(valueDisplayFormat, memValue >> 12, memValue & 0xfff);
                        } else {
                            ImGui::Text(valueDisplayFormat, memValue);
                        }
                        ImGui::TableSetColumnIndex(2);
                        if (displayAsFixedPoint) {
                            ImGui::Text(valueDisplayFormat, scannedValue >> 12, scannedValue & 0xfff);
                        } else {
                            ImGui::Text(valueDisplayFormat, scannedValue);
                        }
                        ImGui::TableSetColumnIndex(3);
                        auto showInMemEditorButtonName = fmt::format(f_("Show in memory editor##{}"), row);
                        if (ImGui::Button(showInMemEditorButtonName.c_str())) {
                            const uint32_t editorAddress = currentAddress - memBase;
                            g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{editorAddress, stride});
                        }
                        ImGui::TableSetColumnIndex(4);
                        auto addReadBreakpointButtonName = fmt::format(f_("Add read breakpoint##{}"), row);
                        if (ImGui::Button(addReadBreakpointButtonName.c_str())) {
                            g_emulator->m_debug->addBreakpoint(currentAddress, Debug::BreakpointType::Read, stride, _("Memory Observer"));
                        }
                        ImGui::TableSetColumnIndex(5);
                        auto addWriteBreakpointButtonName = fmt::format(f_("Add write breakpoint##{}"), row);
                        if (ImGui::Button(addWriteBreakpointButtonName.c_str())) {
                            g_emulator->m_debug->addBreakpoint(currentAddress, Debug::BreakpointType::Write, stride, _("Memory Observer"));
                        }
                    }
                }
                ImGui::EndTable();
            }

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem(_("Pattern search"))) {
            if (m_useSIMD) {
                ImGui::TextUnformatted(_("Sequence size: "));
                ImGui::SameLine();
                ImGui::RadioButton(_("8 bytes (fast)"), &m_sequenceSize, 8);
                ImGui::SameLine();
                ImGui::RadioButton(_("16 bytes (fast)"), &m_sequenceSize, 16);
                ImGui::SameLine();
                ImGui::RadioButton(_("Arbitrary"), &m_sequenceSize, 255);
            }

            ImGui::InputText(_("Sequence"), m_sequence, m_sequenceSize + 1);

            ImGui::InputInt(_("Step"), &m_step);

            if (m_step >= 1 && ImGui::Button(_("Search"))) {
                if (m_useSIMD && m_sequenceSize == 8) {
                    simd_populateAddressList<8>(memData, memBase, memSize);
                } else if (m_useSIMD && m_sequenceSize == 16) {
                    simd_populateAddressList<16>(memData, memBase, memSize);
                } else {
                    populateAddressList(memData, memBase, memSize);
                }
            }

            if (ImGui::BeginTable(_("Found values"), 2, tableFlags)) {
                ImGui::TableSetupColumn(_("Address"));
                ImGui::TableSetupColumn(_("Access"));
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
                        auto buttonName = fmt::format(f_("Show in memory editor##{}"), row);
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

uint8_t PCSX::Widgets::MemoryObserver::getStrideFromValueType(ScanValueType valueType) {
    switch (valueType) {
    case ScanValueType::Char:
    case ScanValueType::Uchar:
        return 1;
    case ScanValueType::Short:
    case ScanValueType::Ushort:
        return 2;
    case ScanValueType::Int:
        return 4;
    default:
        throw std::runtime_error("Invalid value type.");
    }
}

int PCSX::Widgets::MemoryObserver::getValueAsSelectedType(int memValue) {
    switch (m_scanValueType) {
        case ScanValueType::Char:
            int8_t char_val;
            memcpy(&char_val, &memValue, 1);
            return char_val;
        case ScanValueType::Uchar:
            uint8_t uchar_val;
            memcpy(&uchar_val, &memValue, 1);
            return uchar_val;
        case ScanValueType::Short:
            short short_val;
            memcpy(&short_val, &memValue, 2);
            return short_val;
        case ScanValueType::Ushort:
            unsigned short ushort_val;
            memcpy(&ushort_val, &memValue, 2);
            return ushort_val;
        case ScanValueType::Int:
            return memValue;
        default:
            throw std::runtime_error("Invalid value type.");
    }
}

int PCSX::Widgets::MemoryObserver::getMemValue(uint32_t absoluteAddress, const uint8_t* memData, uint32_t memSize,
                                               uint32_t memBase, uint8_t stride) {
    int memValue = 0;
    const uint32_t relativeAddress = absoluteAddress - memBase;
    assert(relativeAddress < memSize);
    for (uint32_t i = relativeAddress; i < relativeAddress + stride; ++i) {
        const uint8_t currentByte = memData[i];
        const uint8_t leftShift = 8 * (i % stride);
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
AVX2_FUNC bool PCSX::Widgets::MemoryObserver::all_equal(__m256i vec) {
    const __m128i vec128 = _mm256_castsi256_si128(vec);
    const __m256i broadcasted = _mm256_broadcastb_epi8(vec128);
    const __m256i res = _mm256_xor_si256(vec, broadcasted);

    // Check if the vector after xoring is 0
    return _mm256_testz_si256(res, res) != 0;
}
#endif  // MEMORY_OBSERVER_X86

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
    for (auto i = 0; i + sequenceSize < memSize; i += m_step) {
        std::copy_n(memData + i, sequenceSize, buffer.data());

        if (matchesPattern(buffer, patternShuffleResults)) {
            m_addresses.push_back(memBase + i);
        }
    }
}
