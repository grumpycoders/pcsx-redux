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

#include "gui/widgets/memory_observer.h"

#include <magic_enum/include/magic_enum.hpp>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/system.h"

void PCSX::Widgets::MemoryObserver::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    uint8_t* memData = g_emulator->m_psxMem->g_psxM;
    uint32_t memSize = 8 * 1024 * 1024;
    uint32_t memBase = 0x80000000;
    const auto stride = static_cast<uint8_t>(m_scanAlignment);

    if (m_AddressValuePairs.empty() && ImGui::Button("First scan")) {

        int memValue = 0;

        for (uint32_t i = 0; i < memSize; ++i) {
            if (i != 0 && i % stride == 0) {
                switch (m_scanType) {
                    case ScanType::ExactValue:
                        if (memValue == m_value) {
                            m_AddressValuePairs.push_back({memBase + i - stride, memValue});
                        }
                        break;
                    case ScanType::BiggerThan:
                        if (memValue < m_value) {
                            m_AddressValuePairs.push_back({memBase + i - stride, memValue});
                        }
                        break;
                    case ScanType::SmallerThan:
                        if (memValue > m_value) {
                            m_AddressValuePairs.push_back({memBase + i - stride, memValue});
                        }
                        break;
                    case ScanType::Changed:
                    case ScanType::Unchanged:
                    case ScanType::Increased:
                    case ScanType::Decreased:
                        break;
                    case ScanType::UnknownInitialValue:
                        m_AddressValuePairs.push_back({memBase + i - stride, memValue});
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

    if (!m_AddressValuePairs.empty() && ImGui::Button("Next scan")) {
        auto doesntMatchCriterion = [this, memData, memSize, memBase, stride](
            const AddressValuePair& addressValuePair) {
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

        std::erase_if(m_AddressValuePairs, doesntMatchCriterion);

        if (m_AddressValuePairs.empty()) {
            m_scanType = ScanType::ExactValue;
        } else {
            for (auto& addressValuePair : m_AddressValuePairs) {
                addressValuePair.scannedValue =
                    getMemValue(addressValuePair.address, memData, memSize, memBase, stride);
            }
        }
    }

    if (!m_AddressValuePairs.empty() && ImGui::Button("New scan")) {
        m_AddressValuePairs.clear();
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

    ImGui::Checkbox(_("Show memory contents"), &m_showMemoryEditor);

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                             ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    if (ImGui::BeginTable("Found values", 4, flags)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Current value");
        ImGui::TableSetupColumn("Scanned value");
        ImGui::TableSetupColumn("Access");
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(m_AddressValuePairs.size());
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& addressValuePair = m_AddressValuePairs[row];
                const uint32_t currentAddress = addressValuePair.address;

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%x", currentAddress);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%i", getMemValue(currentAddress, memData, memSize, memBase, stride));
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%i", addressValuePair.scannedValue);
                ImGui::TableSetColumnIndex(3);
                auto buttonName = fmt::format(_("Show in memory editor##{}"), row);
                if (ImGui::Button(buttonName.c_str())) {
                    m_showMemoryEditor = true;
                    const uint32_t editorAddress = currentAddress - memBase;
                    m_memoryEditor.GotoAddrAndHighlight(editorAddress, editorAddress + stride);
                }
            }
        }
        ImGui::EndTable();
    }

    if (m_showMemoryEditor) {
        m_memoryEditor.DrawWindow(_("Memory Viewer"), memData, memSize, memBase);
    }
}

PCSX::Widgets::MemoryObserver::MemoryObserver() {
    m_memoryEditor.OptShowDataPreview = true;
    m_memoryEditor.OptUpperCaseHex = false;
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
