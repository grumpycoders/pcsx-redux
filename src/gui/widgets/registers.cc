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

#include "core/disr3000a.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"

void PCSX::Widgets::Registers::draw(PCSX::GUI* gui, PCSX::psxRegisters* registers, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(1040, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(210, 512), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    std::string editorToOpen;

    if (ImGui::BeginTabBar(_("Registers"))) {
        gui->useMonoFont();
        if (ImGui::BeginTabItem("GPR")) {
            unsigned counter = 0;
            for (auto& reg : registers->GPR.r) {
                const char* name;
                if (counter >= 32) {
                    switch (counter) {
                        case 32:
                            name = "hi";
                            break;
                        case 33:
                            name = "lo";
                            break;
                        default:
                            name = "??";
                            break;
                    }
                } else {
                    name = PCSX::Disasm::s_disRNameGPR[counter];
                }
                counter++;
                std::string label = fmt::format(_("Edit##{}"), name);
                ImGui::Text("%s: %08x", name, reg);
                ImGui::SameLine();
                if (ImGui::SmallButton(label.c_str())) {
                    editorToOpen = fmt::format(_("Edit value of {}"), name);
                    snprintf(m_registerEditor, 19, "%08x", reg);
                }
            }
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
            auto v0 = registers->CP2D.n.v0;
            ImGui::Text("v0  : {%i, %i, %i}", v0.x, v0.y, v0.z);
            auto v1 = registers->CP2D.n.v1;
            ImGui::Text("v1  : {%i, %i, %i}", v1.x, v1.y, v1.z);
            auto v2 = registers->CP2D.n.v2;
            ImGui::Text("v2  : {%i, %i, %i}", v2.x, v2.y, v2.z);
            auto rgb = registers->CP2D.n.rgb;
            ImGui::Text("rgb : {%i, %i, %i, %i}", rgb.r, rgb.g, rgb.b, rgb.c);
            ImGui::Text("otz : %i", registers->CP2D.n.otz);
            ImGui::Text("ir0 : %i", registers->CP2D.n.ir0);
            ImGui::Text("ir1 : %i", registers->CP2D.n.ir1);
            ImGui::Text("ir2 : %i", registers->CP2D.n.ir2);
            ImGui::Text("ir3 : %i", registers->CP2D.n.ir3);
            auto sxy0 = registers->CP2D.n.sxy0;
            ImGui::Text("sxy0: {%i, %i}", sxy0.x, sxy0.y);
            auto sxy1 = registers->CP2D.n.sxy1;
            ImGui::Text("sxy0: {%i, %i}", sxy1.x, sxy1.y);
            auto sxy2 = registers->CP2D.n.sxy2;
            ImGui::Text("sxy0: {%i, %i}", sxy2.x, sxy2.y);
            auto sxyp = registers->CP2D.n.sxyp;
            ImGui::Text("sxy0: {%i, %i}", sxyp.x, sxyp.y);
            auto sz0 = registers->CP2D.n.sz0;
            ImGui::Text("sz0 : {%i, %i}", sz0.z, sz0.unused);
            auto sz1 = registers->CP2D.n.sz1;
            ImGui::Text("sz1 : {%i, %i}", sz1.z, sz1.unused);
            auto sz2 = registers->CP2D.n.sz2;
            ImGui::Text("sz2 : {%i, %i}", sz2.z, sz2.unused);
            auto sz3 = registers->CP2D.n.sz3;
            ImGui::Text("sz3 : {%i, %i}", sz3.z, sz3.unused);
            auto rgb0 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb0: {%i, %i, %i, %i}", rgb0.r, rgb0.g, rgb0.b, rgb0.c);
            auto rgb1 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb1: {%i, %i, %i, %i}", rgb1.r, rgb1.g, rgb1.b, rgb1.c);
            auto rgb2 = registers->CP2D.n.rgb0;
            ImGui::Text("rgb2: {%i, %i, %i, %i}", rgb2.r, rgb2.g, rgb2.b, rgb2.c);
            ImGui::Text("mac0: %i", registers->CP2D.n.mac0);
            ImGui::Text("mac1: %i", registers->CP2D.n.mac1);
            ImGui::Text("mac2: %i", registers->CP2D.n.mac2);
            ImGui::Text("mac3: %i", registers->CP2D.n.mac3);
            ImGui::Text("irgb: %u", registers->CP2D.n.irgb);
            ImGui::Text("orgb: %u", registers->CP2D.n.orgb);
            ImGui::Text("lzcs: %i", registers->CP2D.n.lzcs);
            ImGui::Text("lzcr: %i", registers->CP2D.n.lzcr);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CP2C")) {
            auto displayMatrix = [](const SMatrix3D& matrix, const char* name) {
                ImGui::Text("   [%5i, %5i, %5i]", matrix.m11, matrix.m12, matrix.m13);
                ImGui::Text("%s: [%5i, %5i, %5i]", name, matrix.m21, matrix.m22, matrix.m23);
                ImGui::Text("   [%5i, %5i, %5i]", matrix.m31, matrix.m32, matrix.m33);
            };
            displayMatrix(registers->CP2C.n.rMatrix, "R");
            ImGui::Text("trX : %i", registers->CP2C.n.trX);
            ImGui::Text("trY : %i", registers->CP2C.n.trY);
            ImGui::Text("trZ : %i", registers->CP2C.n.trZ);
            displayMatrix(registers->CP2C.n.lMatrix, "L");
            ImGui::Text("rbk : %i", registers->CP2C.n.rbk);
            ImGui::Text("gbk : %i", registers->CP2C.n.gbk);
            ImGui::Text("bbk : %i", registers->CP2C.n.bbk);
            displayMatrix(registers->CP2C.n.cMatrix, "C");
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
            ImGui::Text("flag: %i", registers->CP2C.n.flag);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(_("Misc"))) {
            ImGui::Text("pc   : %08x", registers->pc);
            ImGui::Text("cycle: %08x", registers->cycle);
            ImGui::Text("int  : %08x", registers->interrupt);
            ImGui::EndTabItem();
        }
        ImGui::PopFont();
        ImGui::EndTabBar();
    }

    ImGui::End();

    if (!editorToOpen.empty()) ImGui::OpenPopup(editorToOpen.c_str());
    unsigned counter = 0;
    for (auto& reg : registers->GPR.r) {
        const char* name;
        if (counter >= 32) {
            switch (counter) {
                case 32:
                    name = "hi";
                    break;
                case 33:
                    name = "lo";
                    break;
                default:
                    name = "??";
                    break;
            }
        } else {
            name = PCSX::Disasm::s_disRNameGPR[counter];
        }
        counter++;
        std::string editor = fmt::format(_("Edit value of {}"), name);
        if (ImGui::BeginPopupModal(editor.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text(_("Change the value of register %s:"), name);
            if (ImGui::InputText(_("Register"), m_registerEditor, 20,
                                 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
                char* endPtr;
                uint32_t newReg = strtoul(m_registerEditor, &endPtr, 16);
                if (!*endPtr) {
                    reg = newReg;
                    ImGui::CloseCurrentPopup();
                }
            }
            if (ImGui::Button(_("Cancel"))) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }
}
