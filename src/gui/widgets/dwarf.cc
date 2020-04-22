/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "gui/widgets/dwarf.h"

#include <string>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "fmt/format.h"
#include "imgui.h"

namespace {

void dumpTree(const dwarf::die& node, const PCSX::Elf& elf, int depth = 0) {
    std::string name;
    for (auto& attr : node.attributes()) {
        if (attr.first == dwarf::DW_AT::name) {
            name = to_string(attr.second);
            break;
        }
    }
    std::string label = fmt::format("<{:08x}> {} {}", node.get_section_offset(), to_string(node.tag), name);
    if (!ImGui::TreeNode(label.c_str())) return;
    for (auto& attr : node.attributes()) {
        std::string attribute = fmt::format("{} {}", to_string(attr.first), to_string(attr.second));
        ImGui::Text(attribute.c_str());
    }
    for (auto& child : node) dumpTree(child, elf, depth + 1);
    ImGui::TreePop();
}

}  // namespace

void PCSX::Widgets::Dwarf::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto& elves = g_emulator.m_psxMem->getElves();
    for (auto& e : elves) {
        auto& dw = e.getDwarf();
        if (!dw.valid()) continue;
        for (auto cu : dw.compilation_units()) {
            dumpTree(cu.root(), e);
        }
    }

    ImGui::End();
}
