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

#include <algorithm>
#include <cstdlib>
#include "core/system.h"
#include "fmt/format.h"
#include "gui/widgets/memcard_manager.h"

PCSX::Widgets::MemcardManager::MemcardManager() {
    m_memoryEditor.OptShowDataPreview = true;
    m_memoryEditor.OptUpperCaseHex = false;
}

void PCSX::Widgets::MemcardManager::initTextures() {
    // Initialize the OpenGL textures used for the icon images
    // This must only be called when our OpenGL context is set up
    glGenTextures(15, m_iconTextures);
    for (int i = 0; i < 15; i++) {
        glBindTexture(GL_TEXTURE_2D, m_iconTextures[i]);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

        if (!m_drawPocketstationIcons) {
            glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5_A1, 16, 16);
        } else {
            glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGBA8, 32, 32);
        }
    }
}

bool PCSX::Widgets::MemcardManager::draw(const char* title) {
    bool changed = false;
    Actions action = Actions::None;
    int selectedBlock;

    ImGui::SetNextWindowPos(ImVec2(600, 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(400, 400), ImGuiCond_FirstUseEver);

    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return false;
    }

    // Insert or remove memory cards. Send a SIO IRQ to the emulator if this happens as well.
    if (ImGui::Checkbox(_("Memory Card 1 inserted"),
                        &g_emulator->settings.get<Emulator::SettingMcd1Inserted>().value)) {
        g_emulator->m_sio->interrupt();
        changed = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox(_("Memory Card 2 inserted"),
                        &g_emulator->settings.get<Emulator::SettingMcd2Inserted>().value)) {
        g_emulator->m_sio->interrupt();
        changed = true;
    }
    ImGui::Checkbox(_("Show memory card contents"), &m_showMemoryEditor);
    ImGui::SameLine();
    if (ImGui::Button(_("Save memory card to file"))) {
        g_emulator->m_sio->SaveMcd(m_selectedCard);
    }
    ImGui::SameLine();
    {
        const int otherCard = (m_selectedCard == 1) ? 2 : 1;
        const auto copyButtonText = fmt::format(_("Copy all to card {}"), otherCard);
        if (ImGui::Button(copyButtonText.c_str())) {
            const auto source = m_currentCardData;
            auto dest = PCSX::g_emulator->m_sio->GetMcdData(otherCard);

            std::memcpy(dest, source, PCSX::SIO::MCD_SIZE);
        }
    }

    ImGui::SliderInt("Icon size", &m_iconSize, 16, 512);
    ImGui::SameLine();
    if (ImGui::Checkbox("Draw Pockestation icons", &m_drawPocketstationIcons)) {
        glDeleteTextures(15, m_iconTextures); // Recreate our textures to fit our new format
        initTextures();
    }

    static const char* cardNames[] = {_("Memory card 1"), _("Memory card 2")};
    // Code below is slightly odd because m_selectedCart is 1-indexed while arrays are 0-indexed
    if (ImGui::BeginCombo(_("Card"), cardNames[m_selectedCard - 1])) {
        for (int i = 0; i < 2; i++) {
            if (ImGui::Selectable(cardNames[i], m_selectedCard == i + 1)) {
                m_selectedCard = i + 1;
                m_currentCardData = (uint8_t*)g_emulator->m_sio->GetMcdData(m_selectedCard);
            }
        }
        ImGui::EndCombo();
    }

    static constexpr ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                                  ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                                  ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV;
    PCSX::SIO::McdBlock block; // The current memory card block we're looking into

    if (ImGui::BeginTable("Memory card information", 6, flags)) {
        ImGui::TableSetupColumn("Block number");
        ImGui::TableSetupColumn("Icon");
        ImGui::TableSetupColumn("Title");
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Filename");
        ImGui::TableSetupColumn("Action");
        ImGui::TableHeadersRow();

        for (auto i = 1; i < 16; i++) {
            g_emulator->m_sio->GetMcdBlockInfo(m_selectedCard, i, &block);

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", i);
            ImGui::TableSetColumnIndex(1);
            drawIcon(i, block);

            ImGui::TableSetColumnIndex(2);
            ImGui::Text(block.Title);
            ImGui::TableSetColumnIndex(3);
            ImGui::Text(block.ID);
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s (%dKB)", block.Name, block.Filesize / 1024);
            ImGui::TableSetColumnIndex(5);

            // We have to suffix the action button names with ##number because Imgui
            // can't handle multiple buttons with the same name well
            auto buttonName = fmt::format(_("Format##{}"), i);
            if (ImGui::SmallButton(buttonName.c_str())) {
                g_emulator->m_sio->FormatMcdBlock(m_selectedCard, i);
            }
            ImGui::SameLine();
            
            buttonName = fmt::format(_("Copy##{}"), i);
            if (ImGui::SmallButton(buttonName.c_str())) {
                action = Actions::Copy;
                selectedBlock = i;
                m_pendingAction.popupText = fmt::format("Choose block to copy block {} to", selectedBlock);
            }
            ImGui::SameLine();
            
            buttonName = fmt::format(_("Move##{}"), i);
            if (ImGui::SmallButton(buttonName.c_str())) {
                action = Actions::Move;
                selectedBlock = i;
                m_pendingAction.popupText = fmt::format("Choose block to move block {} to", selectedBlock);
            }
            ImGui::SameLine();

            buttonName = fmt::format(_("Swap##{}"), i);
            if (ImGui::SmallButton(buttonName.c_str())) {
                action = Actions::Swap;
                selectedBlock = i;
                m_pendingAction.popupText = fmt::format("Choose block to swap block {} with", selectedBlock);
            }
        }
        ImGui::EndTable();
    }

    if (m_showMemoryEditor) {
        const auto data = m_currentCardData;
        m_memoryEditor.DrawWindow(_("Memory Card Viewer"), data, PCSX::SIO::MCD_SIZE);
    }

    if (action != Actions::None) {
        m_pendingAction.type = action;
        m_pendingAction.targetCard = m_selectedCard; // Default to current card as the target for the action
        m_pendingAction.sourceBlock = selectedBlock;
        ImGui::OpenPopup(m_pendingAction.popupText.c_str());
    }
    
    ImGui::SetNextWindowPos(ImVec2(600, 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(200, 200), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal(m_pendingAction.popupText.c_str())) {
        if (ImGui::BeginCombo(_("Destination card"), cardNames[m_pendingAction.targetCard - 1])) {
            for (unsigned i = 0; i < 2; i++) {
                if (ImGui::Selectable(cardNames[i], m_pendingAction.targetCard == i + 1)) {
                    m_pendingAction.targetCard = i + 1;
                }
            }
            ImGui::EndCombo();
        }

        if (ImGui::InputText(_("Block"), m_pendingAction.textInput, sizeof(m_pendingAction.textInput),
                             ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
            performAction();
            ImGui::CloseCurrentPopup();
        } else if (ImGui::Button("Cancel")) {
            m_pendingAction.type = Actions::None; // Cancel action
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }

    m_frameCount = (m_frameCount + 1) % 60;
    ImGui::End();
    return changed;
}

void PCSX::Widgets::MemcardManager::drawIcon(int blockNumber, PCSX::SIO::McdBlock& block) {
    int currentFrame = 0; // 1st frame = 0, 2nd frame = 1, 3rd frame = 2 and so on
    const auto texture = m_iconTextures[blockNumber - 1];
    glBindTexture(GL_TEXTURE_2D, texture);

    if (!m_drawPocketstationIcons) {
        const auto animationFrames = block.IconCount;
        // Check if we should display the 3rd frame, then check if we should display the 2nd one
        if (m_frameCount >= 40 && animationFrames == 3) {
            currentFrame = 2;
        } else if (m_frameCount >= 20 && animationFrames >= 2) {
            currentFrame = 1;
        }

        // Pointer to the current frame. Skip 16x16 pixels for each frame
        const auto icon = block.Icon + (currentFrame * 16 * 16);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 16, 16, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, icon);
    } else {
        uint32_t pixels[32 * 32];
        const auto data = m_currentCardData;
        const auto titleFrame = data + blockNumber * PCSX::SIO::MCD_BLOCK_SIZE;

        // Calculate icon offset using the header info documented here
        // https://psx-spx.consoledev.net/pocketstation/#pocketstation-file-headericons
        int iconOffset = 0x80 + (titleFrame[0x2] & 0xf) * 0x80;
        //iconOffset += ~((titleFrame[0x57] * 8 + 0x7f) & 0x7f);
        const auto icon = (uint32_t*)(titleFrame + iconOffset);

        int index = 0;
        for (auto scanline = 0; scanline < 32; scanline++) {
            auto line = icon[scanline];
            
            for (auto pixel = 0; pixel < 32; pixel++) {
                if ((line & 1) != 0) {
                    pixels[index++] = 0xff; // Black
                } else {
                    pixels[index++] = 0xffffffff; // White
                }

                line >>= 1; // lsb = next pixel
            }
        }

        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 32, 32, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    }
    
    ImGui::Image((void*)texture, ImVec2(m_iconSize, m_iconSize));
}

// Perform the pending memory card action (Move, copy, swap)
void PCSX::Widgets::MemcardManager::performAction() {
    // Data of source and dest cards respectively
    auto data1 = m_currentCardData;
    auto data2 = (uint8_t*)g_emulator->m_sio->GetMcdData(m_pendingAction.targetCard);

    const int sourceBlock = m_pendingAction.sourceBlock;
    const int destBlock = std::atoi(m_pendingAction.textInput);
    auto source = data1 + sourceBlock * PCSX::SIO::MCD_BLOCK_SIZE;
    auto dest = data2 + destBlock * PCSX::SIO::MCD_BLOCK_SIZE;

    if (destBlock > 15) { // Invalid block number, do nothing
        m_pendingAction.type = Actions::None;
        return;
    }

    switch (m_pendingAction.type) {
        case Actions::Move:
            std::memcpy(dest, source, PCSX::SIO::MCD_BLOCK_SIZE); // Copy source to dest
            PCSX::g_emulator->m_sio->FormatMcdBlock(m_selectedCard, sourceBlock); // Format source
            break;

        case Actions::Copy: {
            const uint8_t* sourceFrame = data1 + sourceBlock * PCSX::SIO::MCD_SECT_SIZE;
            uint8_t* destFrame = data2 + destBlock * PCSX::SIO::MCD_SECT_SIZE;

            // Copy directory frame for source block to directory frame for dest block
            std::memcpy(destFrame, sourceFrame, PCSX::SIO::MCD_SECT_SIZE);
            // Copy source block to dest block
            std::memcpy(dest, source, PCSX::SIO::MCD_BLOCK_SIZE);
        } break;

        case Actions::Swap: {
            uint8_t* sourceFrame = data1 + sourceBlock * PCSX::SIO::MCD_SECT_SIZE;
            uint8_t* destFrame = data2 + destBlock * PCSX::SIO::MCD_SECT_SIZE;

            // Swap the memory card blocks
            for (auto i = 0; i < PCSX::SIO::MCD_BLOCK_SIZE; i++) {
                std::swap(dest[i], source[i]);
            }

            // Swap the directory frames for the blocks
            for (auto i = 0; i < PCSX::SIO::MCD_SECT_SIZE; i++) {
                std::swap(sourceFrame[i], destFrame[i]);
            }
        } break;
    }

    m_pendingAction.type = Actions::None; // Cancel action
}
