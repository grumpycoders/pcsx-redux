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

#include "gui/widgets/sio1.h"

#include "core/sio1.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"

struct PCSX::SIO1RegisterText {
    const char* description;
    const char* notes;
};

static const int kStatusEntries = 32;
static const int kModeEntries = 16;
static const int kControlEntries = 16;

// Lots of repeating strings. Need to add a value for bits repeated?

static PCSX::SIO1RegisterText status_text[kStatusEntries] = {
    {"TX Ready Flag 1", "(1=Ready/Started)  (depends on CTS) (TX requires CTS)"},  //
    {"RX FIFO Not Empty", "(0=Empty, 1=Not Empty)"},                               //
    {"TX Ready Flag 2", "(1=Ready/Finished) (depends on TXEN and on CTS)"},        //
    {"RX Parity Error", "(0=No, 1=Error; Wrong Parity, when enabled) (sticky)"},   //
    {"RX FIFO Overrun", "(0=No, 1=Error; Received more than 8 bytes) (sticky)"},   //
    {"RX Bad Stop Bit", "(0=No, 1=Error; Bad Stop Bit) (when RXEN) (sticky)"},     //
    {"RX Input Level", "(0=Normal, 1=Inverted) ;only AFTER receiving Stop Bit"},   //
    {"DSR Input Level", "(0=Off, 1=On) (remote DTR) ;DSR not required to be on"},  //
    {"CTS Input Level", "(0=Off, 1=On) (remote RTS) ;CTS required for TX"},        //
    {"Interrupt Request", "(0=None, 1=IRQ) (sticky)"},                             //
    {"Unknown", "(always zero)"},                                                  //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Baudrate Timer", "(15bit timer, decrementing at 33MHz)"},                    //
    {"Unknown", "(usually zero, sometimes all bits set)"},                         //
    {"Unknown", "(usually zero, sometimes all bits set)"},                         //
    {"Unknown", "(usually zero, sometimes all bits set)"},                         //
    {"Unknown", "(usually zero, sometimes all bits set)"},                         //
    {"Unknown", "(usually zero, sometimes all bits set)"},                         //
    {"Unknown", "(usually zero, sometimes all bits set)"}                          //
};

static PCSX::SIO1RegisterText mode_text[kModeEntries] = {
    {"Baudrate Reload Factor", "(1=MUL1, 2=MUL16, 3=MUL64) (or 0=STOP)"},  //
    {"Baudrate Reload Factor", "(1=MUL1, 2=MUL16, 3=MUL64) (or 0=STOP)"},  //
    {"Character Length", "(0=5bits, 1=6bits, 2=7bits, 3=8bits)"},          //
    {"Character Length", "(0=5bits, 1=6bits, 2=7bits, 3=8bits)"},          //
    {"Parity Enable", "(0=No, 1=Enable)"},                                 //
    {"Parity Type", "(0=Even, 1=Odd) (seems to be vice-versa...?)"},       //
    {"Stop bit length", "(0=Reserved/1bit, 1=1bit, 2=1.5bits, 3=2bits)"},  //
    {"Stop bit length", "(0=Reserved/1bit, 1=1bit, 2=1.5bits, 3=2bits)"},  //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"},                                         //
    {"Not used", "(always zero)"}                                          //
};

static PCSX::SIO1RegisterText control_text[kControlEntries] = {
    {"TX Enable (TXEN)", "(0=Disable, 1=Enable, when CTS=On)"},                      //
    {"DTR Output Level", "(0=Off, 1=On)"},                                           //
    {"RX Enable (RXEN)", "(0=Disable, 1=Enable)  ;Disable also clears RXFIFO"},      //
    {"TX Output Level", "(0=Normal, 1=Inverted, during Inactivity & Stop bits)"},    //
    {"Acknowledge", "(0=No change, 1=Reset SIO_STAT.Bits 3,4,5,9) (W)"},             //
    {"RTS Output Level", "(0=Off, 1=On)"},                                           //
    {"Reset", "(0=No change, 1=Reset most SIO_registers to zero) (W)"},              //
    {"Unknown?", "(read/write-able when FACTOR non-zero) (otherwise always zero)"},  //
    {"RX Interrupt Mode", "(0..3 = IRQ when RX FIFO contains 1,2,4,8 bytes)"},       //
    {"RX Interrupt Mode", "(0..3 = IRQ when RX FIFO contains 1,2,4,8 bytes)"},       //
    {"TX Interrupt Enable", "(0=Disable, 1=Enable) ;when SIO_STAT.0-or-2 ;Ready"},   //
    {"RX Interrupt Enable", "(0=Disable, 1=Enable) ;when N bytes in RX FIFO"},       //
    {"DSR Interrupt Enable", "(0=Disable, 1=Enable) ;when SIO_STAT.7  ;DSR=On"},     //
    {"Not used", "(always zero)"},                                                   //
    {"Not used", "(always zero)"},                                                   //
    {"Not used", "(always zero)"}                                                    //
};

static ImGuiTableFlags tableFlags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                                    ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable;

void ShowHelpMarker(const char* desc) {
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

template <typename T>
void PCSX::Widgets::SIO1::DrawRegisterEditor(T* reg, const char* regname, SIO1RegisterText* reg_text, int bit_length,
                                             const char* displayformat) {
    bool register_set;
    std::string label;

    const std::string table_name = fmt::format("{}Table", regname);
    char current_value[11];
    const std::string popup_display_text;
    const std::string edit_value_of = fmt::format("Edit value of {}", regname);

    snprintf(current_value, 11, displayformat, *reg);

    ImGui::Text("%s: 0x%s", regname, current_value);
    ImGui::SameLine();
    if (ImGui::Button(_("Edit"))) {
        snprintf(m_registerEditor, 9, displayformat, *reg);
        ImGui::OpenPopup(edit_value_of.c_str());
    }

    if (ImGui::BeginTable(table_name.c_str(), 3, tableFlags)) {
        ImGui::TableSetupColumn(_("Bit"), ImGuiTableColumnFlags_WidthFixed);          // Column 0
        ImGui::TableSetupColumn(_("Description"), ImGuiTableColumnFlags_WidthFixed);  // 1
        ImGui::TableSetupColumn(_("Value"), ImGuiTableColumnFlags_WidthFixed);        // 2
        ImGui::TableHeadersRow();

        for (int row = 0; row < bit_length; row++) {
            ImGui::TableNextRow();
            for (int column = 0; column <= 2; column++) {
                ImGui::TableSetColumnIndex(column);
                switch (column) {
                    case 0:
                        register_set = (*reg >> row) & 1;
                        label = fmt::format("{}", row);

                        if (ImGui::Checkbox(label.c_str(), &register_set)) {
                            if (register_set) {
                                *reg |= (1 << row);
                            } else {
                                *reg &= ~(1 << row);
                            }
                        }
                        break;

                    case 1:
                        ImGui::Text(reg_text[row].description);
                        ImGui::SameLine();
                        ShowHelpMarker(reg_text[row].notes);
                        break;

                    case 2:
                        ImGui::Text("%i", *reg >> row & 1);
                        break;
                }
            }
        }
        ImGui::EndTable();
    }

    // Register editor
    {
        if (ImGui::BeginPopupModal(edit_value_of.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text(_("New value"));
            if ((ImGui::InputText("h", m_registerEditor, (bit_length/4) + 1,
                                  ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) ||
                ImGui::Button(_("OK"))) {
                char* endPtr;
                T newReg = strtoul(m_registerEditor, &endPtr, 16);
                if (!*endPtr) {
                    *reg = newReg;
                    ImGui::CloseCurrentPopup();
                }
            }

            ImGui::SameLine();

            if (ImGui::Button(_("Cancel"))) ImGui::CloseCurrentPopup();

            ImGui::EndPopup();
        }
    }
}

void PCSX::Widgets::SIO1::draw(GUI* gui, SIO1Registers* regs, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(1040, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(210, 512), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    float width = ImGui::GetContentRegionAvail().x / 3.0f;

    // Status
    {
        ImGui::BeginChild("ChildLStatus", ImVec2(width, 0), true);

        DrawRegisterEditor<uint32_t>(&regs->status, "Status", status_text, 32, "%08x");

        ImGui::EndChild();
    }

    ImGui::SameLine();

    // Mode
    {
        ImGui::BeginChild("ChildMMode", ImVec2(width, 0), true);

        DrawRegisterEditor<uint16_t>(&regs->mode, "Mode", mode_text, 16, "%04x");

        ImGui::EndChild();
    }

    ImGui::SameLine();

    // Control
    {
        ImGui::BeginChild("ChildRControl", ImVec2(width, 0), true);

        DrawRegisterEditor<uint16_t>(&regs->control, "Control", control_text, 16, "%04x");

        ImGui::EndChild();
    }

    ImGui::End();
}
