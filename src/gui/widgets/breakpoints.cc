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

#include "gui/widgets/breakpoints.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "fmt/format.h"
#include "imgui.h"
#include "support/imgui-helpers.h"

// Note: We ignore SWL and SWR
static uint32_t getValueAboutToWrite() {
    uint32_t opcode = PCSX::g_emulator->m_mem->read32(PCSX::g_emulator->m_cpu->m_regs.pc);
    uint32_t storeType = opcode >> 26;
    uint32_t reg = ((opcode >> 16) & 0x1F);
    uint32_t mask = (storeType == 0x28) ? 0xff : (storeType == 0x29) ? 0xffff : 0xffffffff;
    return PCSX::g_emulator->m_cpu->m_regs.GPR.r[reg] & mask;
}

static const char* getBreakpointConditionName(PCSX::Debug::BreakpointCondition condition) {
    switch (condition) {
        case PCSX::Debug::BreakpointCondition::Always:
            return _("Always");
        case PCSX::Debug::BreakpointCondition::Greater:
            return _("Greater");
        case PCSX::Debug::BreakpointCondition::Less:
            return _("Less");
        case PCSX::Debug::BreakpointCondition::Change:
            return _("Change");
        case PCSX::Debug::BreakpointCondition::Equal:
            return _("Equal");
    }
    return _("Unknown");
}

static uint32_t getMemoryValue(uint32_t addr, int width, bool isSigned) {

    union MemVal {
        uint32_t uVal;
        int32_t sVal;
    };

    MemVal final = {};
    switch (width) {
        case 1: {
            uint8_t val = PCSX::g_emulator->m_mem->read8(addr);
            if (isSigned) {
                final.uVal = val << 24;
                final.sVal = final.sVal >> 24;
            } else {
                final.uVal = val;
            }
        }
        break;
        case 2: {
            uint16_t val = PCSX::g_emulator->m_mem->read16(addr);
            if (isSigned) {
                final.uVal = val << 16;
                final.sVal = final.sVal >> 16;
            } else {
                final.uVal = val;
            }
        }
        break;
        case 4: 
            final.uVal = PCSX::g_emulator->m_mem->read32(addr);
            break;
    }
    return final.uVal;
}

static ImVec4 s_normalColor = ImColor(0xff, 0xff, 0xff);
static ImVec4 s_hitColor = ImColor(0xff, 0x00, 0x00);

void PCSX::Widgets::Breakpoints::draw(const char* title) {
    ImGui::SetNextWindowPos(ImVec2(520, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }
    auto& debugger = PCSX::g_emulator->m_debug;

    const Debug::Breakpoint* toErase = nullptr;
    auto& tree = debugger->getTree();

    int counter = 0;
    if (!tree.empty()) {
        static ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_Resizable |
                                       ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
                                       ImGuiTableFlags_ContextMenuInBody;

        if (ImGui::BeginTable("Breakpoints", 5, flags)) {
            ImGui::TableSetupColumn("#");
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Active");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Label");
            ImGui::TableHeadersRow();

            const uint32_t pc = PCSX::g_emulator->m_cpu->m_regs.pc;

            int row = 0;
            for (auto bp = tree.begin(); bp != tree.end(); bp++, row++) {
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(((bp->address() | bp->base()) == pc) ? s_hitColor : s_normalColor, "%d", row);

                ImGui::TableNextColumn();
                std::string buttonStr = fmt::format("{:08x}", bp->address() | bp->base());
                if (ImGui::Button(buttonStr.c_str(), ImVec2(-FLT_MIN, 0.0f))) {
                    if (bp->type() == Debug::BreakpointType::Exec) {
                        g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{bp->address() | bp->base()});
                    } else {
                        g_system->m_eventBus->signal(
                            PCSX::Events::GUI::JumpToMemory{bp->address() | bp->base(), bp->width(), 0, true});
                    }
                }
                if (ImGui::BeginPopupContextItem()) {
                    ImGui::TextUnformatted(_("Delete Breakpoint?"));
                    if (ImGui::Button(_("Delete"))) {
                        toErase = &*bp;
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }

                ImGui::TableNextColumn();
                bool enabled = bp->enabled();
                ImGui::PushID(row);
                if (ImGui::Checkbox("", &enabled)) {
                    if (bp->enabled()) {
                        bp->disable();
                    } else {
                        bp->enable();
                    }
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                std::string textStr;
                if (bp->type() == Debug::BreakpointType::Exec) {
                    textStr =
                        fmt::format("{} {}", Debug::s_breakpoint_type_names[(unsigned)bp->type()](), bp->source());
                } else {
                    textStr = fmt::format("{}:{} {} {} {}", Debug::s_breakpoint_type_names[(unsigned)bp->type()](),
                                          bp->width(), bp->source(), getBreakpointConditionName(bp->condition()), bp->conditionData());
                }
                ImGui::TextUnformatted(textStr.c_str());

                ImGui::TableNextColumn();
                ImGui::PushItemWidth(0);
                char labelText[256];
                strcpy(labelText, bp->label().c_str());
                ImGui::PushID(row + 1000);
                if (ImGui::InputText("", labelText, sizeof(labelText))) {
                    bp->label(labelText);
                }
                ImGui::PopID();
                ImGui::PopItemWidth();
            }
            ImGui::EndTable();
        }
    }

    if (ImGui::Button(_("Add Breakpoint..."))) {
        ImGui::OpenPopup("BreakpointPopup");
    }

    if (ImGui::BeginPopupContextItem("BreakpointPopup")) {
        ImGui::InputText(_("Address"), m_bpAddressString, sizeof(m_bpAddressString),
                            ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_AutoSelectAll);
        if (ImGui::BeginCombo(_("Type"), Debug::s_breakpoint_type_names[m_breakpointType]())) {
            for (int i = 0; i < 3; i++) {
                if (ImGui::Selectable(Debug::s_breakpoint_type_names[i](), m_breakpointType == i)) {
                    m_breakpointType = i;
                }
            }
            ImGui::EndCombo();
        }

        static int range = 8;
        static int width = 1;
        if (m_breakpointType != (int)Debug::BreakpointType::Exec) {
            ImGui::RadioButton(_("Byte"), &width, 1);
            ImGui::RadioButton(_("Half"), &width, 2);
            ImGui::RadioButton(_("Word"), &width, 4);
            ImGui::RadioButton(_("Range"), &width, 0);

            if (width == 0) {
                ImGui::InputInt(_("Byte Width"), &range);
            }
        }

        int actualWidth = (width == 0) ? range : width;

        char* endPtr;
        uint32_t breakpointAddress = strtoul(m_bpAddressString, &endPtr, 16);

        static int breakConditionImguiValue = 0;
        static int conditionVal = 0;

        Debug::BreakpointCondition breakCondition; 
        Debug::BreakpointType type = (Debug::BreakpointType)m_breakpointType;
        if (type != Debug::BreakpointType::Exec) {
            ImGui::Combo(_("Break Condition"), &breakConditionImguiValue, _("Always\0Change\0Greater\0Less\0Equal\0"));
            breakCondition = (Debug::BreakpointCondition)breakConditionImguiValue;

            switch (breakCondition) {
                default:
                case Debug::BreakpointCondition::Always:
                case Debug::BreakpointCondition::Change:
                    break;

                case Debug::BreakpointCondition::Equal:
                case Debug::BreakpointCondition::Less:
                case Debug::BreakpointCondition::Greater:
                    ImGui::InputInt(_("Value"), &conditionVal);
                    uint32_t curVal = getMemoryValue(breakpointAddress, actualWidth, false);
                    std::string buttonStr = fmt::format("{:08x} ({})", curVal, curVal);
                    if (ImGui::Button(buttonStr.c_str())) {
                        conditionVal = curVal;
                    }
                    ImGui::SameLine();
                    ImGui::Text(_("Current Value"));
                    break;
            }
        }

        ImGui::InputText(_("Label"), m_bpLabelString, sizeof(m_bpLabelString));

        if (ImGui::Button(_("Add"))) {
            if (*m_bpAddressString && !*endPtr) {
                Debug::BreakpointType bpType = Debug::BreakpointType(m_breakpointType);

                Debug::BreakpointInvoker invoker = [](Debug::Breakpoint* self, uint32_t address, unsigned width,
                                                      const char* cause) {

                    switch (self->type())
                    {
                        case Debug::BreakpointType::Exec:
                            g_system->pause();
                            break;

                        case Debug::BreakpointType::Write: {
                            // We can't rely on data in memory since the bp triggers before the instruction executes
                            // So we grab the value to be written directly from the instruction itself
                            uint32_t curVal = getValueAboutToWrite();
                            bool doBreak = true;
                            switch (self->condition()) {
                                default:
                                case Debug::BreakpointCondition::Always:
                                    break;
                                case Debug::BreakpointCondition::Greater:
                                    doBreak = curVal > self->conditionData();
                                    break;
                                case Debug::BreakpointCondition::Less:
                                    doBreak = curVal < self->conditionData();
                                    break;
                                case Debug::BreakpointCondition::Change:
                                    doBreak = curVal != self->conditionData();
                                    if (doBreak) {
                                        self->setConditionData(curVal);
                                    }
                                    break;
                                case Debug::BreakpointCondition::Equal:
                                    doBreak = curVal == self->conditionData();
                                    break;
                            }
                            if (doBreak) {
                                g_system->printf(_("Breakpoint condition met! Type:%s writing:%d condVal:%d\n"),
                                                 getBreakpointConditionName(self->condition()), curVal,
                                                 self->conditionData());
                                g_system->pause();
                            }
                        } break;

                        case Debug::BreakpointType::Read: {
                            uint32_t curVal = getMemoryValue(self->address(), self->width(), false);
                            bool doBreak = true;
                            switch (self->condition()) {
                                default:
                                case Debug::BreakpointCondition::Always:
                                    break;
                                case Debug::BreakpointCondition::Greater:
                                    doBreak = curVal > self->conditionData();
                                    break;
                                case Debug::BreakpointCondition::Less:
                                    doBreak = curVal < self->conditionData();
                                    break;
                                case Debug::BreakpointCondition::Change:
                                    doBreak = curVal != self->conditionData();
                                    if (doBreak) {
                                        self->setConditionData(curVal);
                                    }
                                    break;
                                case Debug::BreakpointCondition::Equal:
                                    doBreak = curVal == self->conditionData();
                                    break;
                            }
                            if (doBreak) {
                                g_system->printf(_("Breakpoint condition met! Type:%s reading:%d condVal:%d\n"),
                                                 getBreakpointConditionName(self->condition()), curVal,
                                                 self->conditionData());
                                g_system->pause();
                            }

                        } break;
                    }
                    return true;
                };

                uint32_t conditionData = 0;
                switch (breakCondition) {
                    default:
                    case Debug::BreakpointCondition::Always:
                        break;
                    case Debug::BreakpointCondition::Equal:
                        conditionData = conditionVal;
                        break;
                    case Debug::BreakpointCondition::Less:
                    case Debug::BreakpointCondition::Greater:
                    case Debug::BreakpointCondition::Change:
                        conditionData = conditionVal;
                        break;
                }

                Debug::Breakpoint* bp = debugger->addBreakpoint(breakpointAddress, bpType,
                                                     (bpType == Debug::BreakpointType::Exec) ? 4 : actualWidth, _("GUI"),
                                                       m_bpLabelString, invoker);

                bp->setCondition(breakCondition);
                bp->setConditionData(conditionData);

                // we clear the label string because it seems more likely that the user would forget to clear the
                // field than that they want to use the same label twice
                m_bpLabelString[0] = 0;
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::EndPopup();
    }

    if (!tree.empty()) {
        ImGui::SameLine();
        if (ImGui::Button(_("Activate All"))) {
            for (auto bp = tree.begin(); bp != tree.end(); bp++) {
                bp->enable();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button(_("Deactivate All"))) {
            for (auto bp = tree.begin(); bp != tree.end(); bp++) {
                bp->disable();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button(_("Delete All"))) {
            ImGui::OpenPopup("delbp_popup");
        }
        if (ImGui::BeginPopup("delbp_popup")) {
            ImGui::TextUnformatted(_("Delete all Breakpoints?"));
            if (ImGui::Button(_("Delete"))) {
                g_emulator->m_debug->removeAllBreakpoints();
            }
            ImGui::EndPopup();
        }
    }

    ImGui::Separator();
    if (ImGui::TreeNode(_("Execution Map"))) {
        if (ImGui::Button(_("Clear maps"))) {
            debugger->clearMaps();
        }
        ImGuiHelpers::ShowHelpMarker(
            _("The mapping feature is a simple concept, but requires some amount of explanation. See the documentation "
              "website for more details, in the Misc Features subsection of the Debugging section."));
        ImGui::Checkbox(_("Map execution"), &debugger->m_mapping_e);
        ImGui::Checkbox(_("Map byte reads         "), &debugger->m_mapping_r8);
        ImGui::SameLine();
        ImGui::Checkbox(_("Map half reads         "), &debugger->m_mapping_r16);
        ImGui::SameLine();
        ImGui::Checkbox(_("Map word reads         "), &debugger->m_mapping_r32);
        ImGui::Checkbox(_("Map byte writes        "), &debugger->m_mapping_w8);
        ImGui::SameLine();
        ImGui::Checkbox(_("Map half writes        "), &debugger->m_mapping_w16);
        ImGui::SameLine();
        ImGui::Checkbox(_("Map word writes        "), &debugger->m_mapping_w32);
        ImGui::Separator();
        ImGui::Checkbox(_("Break on execution map"), &debugger->m_breakmp_e);
        ImGui::Checkbox(_("Break on byte read map "), &debugger->m_breakmp_r8);
        ImGui::SameLine();
        ImGui::Checkbox(_("Break on half read map "), &debugger->m_breakmp_r16);
        ImGui::SameLine();
        ImGui::Checkbox(_("Break on word read map "), &debugger->m_breakmp_r32);
        ImGui::Checkbox(_("Break on byte write map"), &debugger->m_breakmp_w8);
        ImGui::SameLine();
        ImGui::Checkbox(_("Break on half write map"), &debugger->m_breakmp_w16);
        ImGui::SameLine();
        ImGui::Checkbox(_("Break on word write map"), &debugger->m_breakmp_w32);
        ImGui::TreePop();
    }

    if (toErase) g_emulator->m_debug->removeBreakpoint(toErase);
    ImGui::End();
}
