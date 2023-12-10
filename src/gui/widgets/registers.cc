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

#include "gui/widgets/registers.h"

#include <cmath>
#include <numbers>

#include "core/disr3000a.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"

void PCSX::Widgets::Registers::makeEditableRegister(const char* name, uint32_t reg) {
    std::string contextLabel = fmt::format(f_("Context##{}"), name);
    if (ImGui::BeginPopupContextItem(contextLabel.c_str())) {
        if (ImGui::MenuItem(_("Go to in Assembly"))) {
            g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{reg});
        }
        if (ImGui::MenuItem(_("Go to in Memory Editor"))) {
            g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{reg, 1});
        }
        if (ImGui::MenuItem(_("Copy Value"))) {
            char strVal[10];
            std::snprintf(strVal, sizeof(strVal), "%8.8x", reg);
            ImGui::SetClipboardText(strVal);
        }
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    std::string label = fmt::format(f_("Edit##{}"), name);
    if (ImGui::SmallButton(label.c_str())) {
        m_editorToOpen = fmt::format(f_("Edit value of {}"), name);
        snprintf(m_registerEditor, 19, "%08x", reg);
    }
}

void PCSX::Widgets::Registers::draw(PCSX::GUI* gui, PCSX::psxRegisters* registers, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(1040, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(210, 512), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar(_("Registers"))) {
        gui->useMonoFont();
        if (ImGui::BeginTabItem("GPR")) {
            unsigned counter = 0;
            for (auto& reg : registers->GPR.r) {
                const char* name;
                if (counter >= 32) {
                    switch (counter) {
                        case 32:
                            name = "lo";
                            break;
                        case 33:
                            name = "hi";
                            break;
                        default:
                            name = "??";
                            break;
                    }
                } else {
                    name = PCSX::Disasm::s_disRNameGPR[counter];
                }
                ImGui::Text("%s: %08x", name, reg);
                makeEditableRegister(name, reg);
                counter++;
            }
            ImGui::Separator();
            ImGui::Text("pc: %08x", registers->pc);
            makeEditableRegister("pc", registers->pc);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CP0")) {
            unsigned counter = 0;
            for (auto& reg : registers->CP0.r) {
                const char* name = PCSX::Disasm::s_disRNameCP0[counter++];
                ImGui::Text("%9s: %08x", name, reg);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CP2D")) {
            ImGui::Checkbox(_("Show fixed point"), &m_showFixed);
            auto v0 = registers->CP2D.n.v0;
            if (m_showFixed) {
                ImGui::Text("v0  : {% 3.5f, % 3.5f, % 3.5f}", fixedToFloat(v0.x), fixedToFloat(v0.y),
                            fixedToFloat(v0.z));
            } else {
                ImGui::Text("v0  : {%i, %i, %i}", v0.x, v0.y, v0.z);
            }
            auto v1 = registers->CP2D.n.v1;
            if (m_showFixed) {
                ImGui::Text("v1  : {% 3.5f, % 3.5f, % 3.5f}", fixedToFloat(v1.x), fixedToFloat(v1.y),
                            fixedToFloat(v1.z));
            } else {
                ImGui::Text("v1  : {%i, %i, %i}", v1.x, v1.y, v1.z);
            }
            auto v2 = registers->CP2D.n.v2;
            if (m_showFixed) {
                ImGui::Text("v2  : {% 3.5f, % 3.5f, % 3.5f}", fixedToFloat(v2.x), fixedToFloat(v2.y),
                            fixedToFloat(v2.z));
            } else {
                ImGui::Text("v2  : {%i, %i, %i}", v2.x, v2.y, v2.z);
            }
            auto rgb = registers->CP2D.n.rgb;
            ImGui::Text("rgb : {%i, %i, %i, %i}", rgb.r, rgb.g, rgb.b, rgb.c);
            if (m_showFixed) {
                ImGui::Text("otz : % 3.5f", fixedToFloat(registers->CP2D.n.otz));
            } else {
                ImGui::Text("otz : %i", registers->CP2D.n.otz);
            }
            if (m_showFixed) {
                ImGui::Text("ir0 : % 3.5f", fixedToFloat(registers->CP2D.n.ir0));
            } else {
                ImGui::Text("ir0 : %i", registers->CP2D.n.ir0);
            }
            if (m_showFixed) {
                ImGui::Text("ir1 : % 3.5f", fixedToFloat(registers->CP2D.n.ir1));
            } else {
                ImGui::Text("ir1 : %i", registers->CP2D.n.ir1);
            }
            if (m_showFixed) {
                ImGui::Text("ir2 : % 3.5f", fixedToFloat(registers->CP2D.n.ir2));
            } else {
                ImGui::Text("ir2 : %i", registers->CP2D.n.ir2);
            }
            if (m_showFixed) {
                ImGui::Text("ir3 : % 3.5f", fixedToFloat(registers->CP2D.n.ir3));
            } else {
                ImGui::Text("ir3 : %i", registers->CP2D.n.ir3);
            }
            auto sxy0 = registers->CP2D.n.sxy0;
            if (m_showFixed) {
                ImGui::Text("sxy0: {% 3.5f, % 3.5f}", fixedToFloat(sxy0.x), fixedToFloat(sxy0.y));
            } else {
                ImGui::Text("sxy0: {%i, %i}", sxy0.x, sxy0.y);
            }
            auto sxy1 = registers->CP2D.n.sxy1;
            if (m_showFixed) {
                ImGui::Text("sxy1: {% 3.5f, % 3.5f}", fixedToFloat(sxy1.x), fixedToFloat(sxy1.y));
            } else {
                ImGui::Text("sxy1: {%i, %i}", sxy1.x, sxy1.y);
            }
            auto sxy2 = registers->CP2D.n.sxy2;
            if (m_showFixed) {
                ImGui::Text("sxy2: {% 3.5f, % 3.5f}", fixedToFloat(sxy2.x), fixedToFloat(sxy2.y));
            } else {
                ImGui::Text("sxy2: {%i, %i}", sxy2.x, sxy2.y);
            }
            auto sxyp = registers->CP2D.n.sxyp;
            if (m_showFixed) {
                ImGui::Text("sxyp: {% 3.5f, % 3.5f}", fixedToFloat(sxyp.x), fixedToFloat(sxyp.y));
            } else {
                ImGui::Text("sxyp: {%i, %i}", sxyp.x, sxyp.y);
            }
            auto sz0 = registers->CP2D.n.sz0;
            if (m_showFixed) {
                ImGui::Text("sz0 : % 3.5f", fixedToFloat(sz0.z));
            } else {
                ImGui::Text("sz0 : %i", sz0.z);
            }
            auto sz1 = registers->CP2D.n.sz1;
            if (m_showFixed) {
                ImGui::Text("sz1 : % 3.5f", fixedToFloat(sz1.z));
            } else {
                ImGui::Text("sz1 : %i", sz1.z);
            }
            auto sz2 = registers->CP2D.n.sz2;
            if (m_showFixed) {
                ImGui::Text("sz2 : % 3.5f", fixedToFloat(sz2.z));
            } else {
                ImGui::Text("sz2 : %i", sz2.z);
            }
            auto sz3 = registers->CP2D.n.sz3;
            if (m_showFixed) {
                ImGui::Text("sz3 : % 3.5f", fixedToFloat(sz3.z));
            } else {
                ImGui::Text("sz3 : %i", sz3.z);
            }
            auto rgb0 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb0: {%i, %i, %i, %i}", rgb0.r, rgb0.g, rgb0.b, rgb0.c);
            auto rgb1 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb1: {%i, %i, %i, %i}", rgb1.r, rgb1.g, rgb1.b, rgb1.c);
            auto rgb2 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb2: {%i, %i, %i, %i}", rgb2.r, rgb2.g, rgb2.b, rgb2.c);
            if (m_showFixed) {
                ImGui::Text("mac0: % 3.5f", fixedToFloat(registers->CP2D.n.mac0));
            } else {
                ImGui::Text("mac0: %i", registers->CP2D.n.mac0);
            }
            if (m_showFixed) {
                ImGui::Text("mac1: % 3.5f", fixedToFloat(registers->CP2D.n.mac1));
            } else {
                ImGui::Text("mac1: %i", registers->CP2D.n.mac1);
            }
            if (m_showFixed) {
                ImGui::Text("mac2: % 3.5f", fixedToFloat(registers->CP2D.n.mac2));
            } else {
                ImGui::Text("mac2: %i", registers->CP2D.n.mac2);
            }
            if (m_showFixed) {
                ImGui::Text("mac3: % 3.5f", fixedToFloat(registers->CP2D.n.mac3));
            } else {
                ImGui::Text("mac3: %i", registers->CP2D.n.mac3);
            }
            ImGui::Text("irgb: %u", registers->CP2D.n.irgb);
            ImGui::Text("orgb: %u", registers->CP2D.n.orgb);
            if (m_showFixed) {
                ImGui::Text("lzcs: % 3.5f", fixedToFloat(registers->CP2D.n.lzcs));
            } else {
                ImGui::Text("lzcs: %i", registers->CP2D.n.lzcs);
            }
            if (m_showFixed) {
                ImGui::Text("lzcr: % 3.5f", fixedToFloat(registers->CP2D.n.lzcr));
            } else {
                ImGui::Text("lzcr: %i", registers->CP2D.n.lzcr);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CP2C")) {
            ImGui::Checkbox(_("Show fixed point"), &m_showFixed);
            auto showFixed = m_showFixed;
            auto displayMatrixPlain = [](SMatrix3D matrix, const char* name) {
                ImGui::Text("   [%5i, %5i, %5i]", matrix.m11, matrix.m12, matrix.m13);
                ImGui::Text("%s: [%5i, %5i, %5i]", name, matrix.m21, matrix.m22, matrix.m23);
                ImGui::Text("   [%5i, %5i, %5i]", matrix.m31, matrix.m32, matrix.m33);
            };
            auto displayMatrixFixed = [](SMatrix3D matrix, const char* name) {
                ImGui::Text("   [% 3.5f, % 3.5f, % 3.5f]", fixedToFloat(matrix.m11), fixedToFloat(matrix.m12),
                            fixedToFloat(matrix.m13));
                ImGui::Text("%s: [% 3.5f, % 3.5f, % 3.5f]", name, fixedToFloat(matrix.m21), fixedToFloat(matrix.m22),
                            fixedToFloat(matrix.m23));
                ImGui::Text("   [% 3.5f, % 3.5f, % 3.5f]", fixedToFloat(matrix.m31), fixedToFloat(matrix.m32),
                            fixedToFloat(matrix.m33));
            };
            auto displayMatrix = showFixed ? displayMatrixFixed : displayMatrixPlain;
            displayMatrix(registers->CP2C.n.rMatrix, "R");
            if (showFixed) {
                float m11 = fixedToFloat(registers->CP2C.n.rMatrix.m11);
                float m12 = fixedToFloat(registers->CP2C.n.rMatrix.m12);
                float m13 = fixedToFloat(registers->CP2C.n.rMatrix.m13);
                float m21 = fixedToFloat(registers->CP2C.n.rMatrix.m21);
                float m22 = fixedToFloat(registers->CP2C.n.rMatrix.m22);
                float m23 = fixedToFloat(registers->CP2C.n.rMatrix.m23);
                float m31 = fixedToFloat(registers->CP2C.n.rMatrix.m31);
                float m32 = fixedToFloat(registers->CP2C.n.rMatrix.m32);
                float m33 = fixedToFloat(registers->CP2C.n.rMatrix.m33);
                float c11 = m22 * m33 - m23 * m32;
                float c12 = m23 * m31 - m21 * m33;
                float c13 = m21 * m32 - m22 * m31;
                auto trace = m11 + m22 + m33;
                auto determinant = m11 * c11 + m12 * c12 + m13 * c13;
                ImGui::Text(" :: deter: % 3.5f", determinant);
                ImGui::Text(" :: trace: % 3.5f", trace);
                auto angle = std::acos((trace - 1.0) / 2.0);
                ImGui::Text(" :: angle: % 3.5f x Pi", angle / std::numbers::pi);
                float f = 1.0f / (2.0f * std::sin(angle));
                float x = (m32 - m23) * f;
                float y = (m13 - m31) * f;
                float z = (m21 - m12) * f;
                float magnitude = std::sqrt(x * x + y * y + z * z);
                x /= magnitude;
                y /= magnitude;
                z /= magnitude;
                ImGui::Text(" :: axis : {%3.5f, %3.5f, %3.5f}", x, y, z);
            }
            ImGui::Text("trX : %i", registers->CP2C.n.trX);
            ImGui::Text("trY : %i", registers->CP2C.n.trY);
            ImGui::Text("trZ : %i", registers->CP2C.n.trZ);
            displayMatrix(registers->CP2C.n.lMatrix, "L");
            if (showFixed) {
                ImGui::Text("rbk : % 3.5f", fixedToFloat(registers->CP2C.n.rbk));
                ImGui::Text("gbk : % 3.5f", fixedToFloat(registers->CP2C.n.gbk));
                ImGui::Text("bbk : % 3.5f", fixedToFloat(registers->CP2C.n.bbk));
            } else {
                ImGui::Text("rbk : %i", registers->CP2C.n.rbk);
                ImGui::Text("gbk : %i", registers->CP2C.n.gbk);
                ImGui::Text("bbk : %i", registers->CP2C.n.bbk);
            }
            displayMatrix(registers->CP2C.n.cMatrix, "C");
            if (showFixed) {
                ImGui::Text("rfc : % 3.5f", fixedToFloat<4>(registers->CP2C.n.rfc));
                ImGui::Text("gfc : % 3.5f", fixedToFloat<4>(registers->CP2C.n.gfc));
                ImGui::Text("bfc : % 3.5f", fixedToFloat<4>(registers->CP2C.n.bfc));
                ImGui::Text("ofx : % 3.5f", fixedToFloat<15>(registers->CP2C.n.ofx));
                ImGui::Text("ofy : % 3.5f", fixedToFloat<15>(registers->CP2C.n.ofy));
                ImGui::Text("h   : % i", registers->CP2C.n.h);
                ImGui::Text("dqa : % 3.5f", fixedToFloat<8>(registers->CP2C.n.dqa));
                ImGui::Text("dqb : % 3.5f", fixedToFloat<24>(registers->CP2C.n.dqb));
                ImGui::Text("zsf3: % 3.5f", fixedToFloat(registers->CP2C.n.zsf3));
                ImGui::Text("zsf4: % 3.5f", fixedToFloat(registers->CP2C.n.zsf4));
            } else {
                ImGui::Text("rfc : %i", registers->CP2C.n.rfc);
                ImGui::Text("gfc : %i", registers->CP2C.n.gfc);
                ImGui::Text("bfc : %i", registers->CP2C.n.bfc);
                ImGui::Text("ofx : %i", registers->CP2C.n.ofx);
                ImGui::Text("ofy : %i", registers->CP2C.n.ofy);
                ImGui::Text("h   : %i", registers->CP2C.n.h);
                ImGui::Text("dqa : %i", registers->CP2C.n.dqa);
                ImGui::Text("dqb : %i", registers->CP2C.n.dqb);
                ImGui::Text("zsf3: %i", registers->CP2C.n.zsf3);
                ImGui::Text("zsf4: %i", registers->CP2C.n.zsf4);
            }
            ImGui::Text("flag: 0x%08x", registers->CP2C.n.flag);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(_("Misc"))) {
            ImGui::Text("pc   : %08x", registers->pc);
            makeEditableRegister("pc", registers->pc);
            ImGui::Text("cycle: %08x", registers->cycle);
            ImGui::Text("sched: %08x", registers->scheduleMask);
            ImGui::EndTabItem();
        }
        ImGui::PopFont();
        ImGui::EndTabBar();
    }

    ImGui::End();

    if (!m_editorToOpen.empty()) {
        ImGui::OpenPopup(m_editorToOpen.c_str());
        m_editorToOpen = "";
    }
    for (unsigned counter = 0; counter < 35; counter++) {
        const char* name;
        if (counter >= 32) {
            switch (counter) {
                case 32:
                    name = "hi";
                    break;
                case 33:
                    name = "lo";
                    break;
                case 34:
                    name = "pc";
                    break;
                default:
                    name = "??";
                    break;
            }
        } else {
            name = PCSX::Disasm::s_disRNameGPR[counter];
        }
        std::string editor = fmt::format(f_("Edit value of {}"), name);
        if (ImGui::BeginPopupModal(editor.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text(_("Change the value of register %s:"), name);
            if (ImGui::InputText(_("Register"), m_registerEditor, 20,
                                 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
                char* endPtr;
                uint32_t newReg = strtoul(m_registerEditor, &endPtr, 16);
                if (!*endPtr) {
                    if (counter == 34) {
                        registers->pc = newReg;
                    } else {
                        registers->GPR.r[counter] = newReg;
                    }
                    ImGui::CloseCurrentPopup();
                }
            }
            if (ImGui::Button(_("Cancel"))) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }
}
