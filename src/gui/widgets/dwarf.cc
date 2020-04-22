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

void dumpTree(const dwarf::die& node, const PCSX::Elf& elf) {
    std::string name;
    for (auto& attr : node.attributes()) {
        if (attr.first == dwarf::DW_AT::name) {
            name = to_string(attr.second);
            break;
        }
    }
    std::string label = fmt::format("<{:08x}> {:30} {}", node.get_section_offset(), to_string(node.tag), name);
    if (!ImGui::TreeNode(label.c_str())) return;
    for (auto& attr : node.attributes()) {
        if (attr.second.get_type() == dwarf::value::type::reference) {
            const dwarf::die& d = attr.second.as_reference();
            dumpTree(d, elf);
        } else {
            std::string attribute = fmt::format("{:30} {}", to_string(attr.first), to_string(attr.second));
            ImGui::Text(attribute.c_str());
        }
    }
    for (auto& child : node) dumpTree(child, elf);
    ImGui::TreePop();
}

}  // namespace

void PCSX::Widgets::Dwarf::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    static const char* order[] = {
        "Compilation Unit",
        "Offset",
    };

    bool changed = false;
    auto newValue = m_orderBy;
    if (ImGui::BeginCombo(_("Order by"), order[m_orderBy])) {
        for (int i = 0; i < 2; i++) {
            if (ImGui::Selectable(order[i], m_orderBy == i)) {
                changed = true;
                newValue = decltype(m_orderBy)(i);
            }
        }
        ImGui::EndCombo();
    }
    if (changed) m_orderBy = newValue;
    auto& elves = g_emulator.m_psxMem->getElves();
    for (auto& e : elves) {
        switch (m_orderBy) {
            case BY_CU: {
                auto& dw = e.getDwarf();
                if (!dw.valid()) continue;
                for (auto cu : dw.compilation_units()) {
                    dumpTree(cu.root(), e);
                }
                break;
            }
            case BY_OFFSET: {
                for (auto& d : e.getDies()) {
                    dumpTree(d.second, e);
                }
                break;
            }
        }
    }

    ImGui::End();
}
