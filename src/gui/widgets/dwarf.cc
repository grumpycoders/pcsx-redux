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
#include "imgui_stdlib.h"

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
        switch (attr.second.get_type()) {
            case dwarf::value::type::reference: {
                const dwarf::die& d = attr.second.as_reference();
                dumpTree(d, elf);
                break;
            }
            case dwarf::value::type::exprloc: {
                const dwarf::expr& expr = attr.second.as_exprloc();
                std::string result = "[**ERR**]";
                try {
                    auto r = expr.evaluate(&dwarf::no_expr_context);
                    switch (r.location_type) {
                        case dwarf::expr_result::type::address: {
                            result = fmt::format("[Address: {:08x}]", r.value);
                            break;
                        }
                        case dwarf::expr_result::type::reg: {
                            result = fmt::format("[Register: {:02x}]", r.value);
                            break;
                        }
                        case dwarf::expr_result::type::literal: {
                            result = fmt::format("[Literal: {:08x}]", r.value);
                            break;
                        }
                        case dwarf::expr_result::type::implicit: {
                            result = fmt::format("[Implicit: {} bytes]", r.implicit_len);
                            break;
                        }
                        case dwarf::expr_result::type::cfa: {
                            result = "[CFA]";
                            break;
                        }
                        case dwarf::expr_result::type::fbreg: {
                            result = fmt::format("[FBREG: {}]", r.fbregvalue);
                            break;
                        }
                        case dwarf::expr_result::type::empty: {
                            result = "[Empty]";
                            break;
                        }
                    }
                } catch (...) {
                    //__debugbreak();
                }
                std::string attribute = fmt::format("{:30} value: {}", to_string(attr.first), result);
                if (ImGui::TreeNode(attribute.c_str())) {
                    auto strs = expr.to_strings();
                    for (auto& s : strs) {
                        ImGui::Text(s.c_str());
                    }
                    ImGui::TreePop();
                }
                break;
            }
            default: {
                std::string attribute = fmt::format("{:30} {}", to_string(attr.first), to_string(attr.second));
                ImGui::Text(attribute.c_str());
                break;
            }
        }
    }
    for (auto& child : node) dumpTree(child, elf);
    ImGui::TreePop();
}  // namespace

}  // namespace

void PCSX::Widgets::Dwarf::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    static const char* order[] = {"Compilation Unit", "Offset", "PC", "Line Table"};

    bool changed = false;
    auto newValue = m_orderBy;
    if (ImGui::BeginCombo(_("Order by"), order[m_orderBy])) {
        for (int i = 0; i < (sizeof(order) / sizeof(order[0])); i++) {
            if (ImGui::Selectable(order[i], m_orderBy == i)) {
                changed = true;
                newValue = decltype(m_orderBy)(i);
            }
        }
        ImGui::EndCombo();
    }
    if (changed) m_orderBy = newValue;

    if (m_orderBy == BY_PC) ImGui::InputText("PC", &m_pc, ImGuiInputTextFlags_CharsHexadecimal);

    ImGui::BeginChild("tree");
    auto& elves = g_emulator->m_psxMem->getElves();
    for (auto& e : elves) {
        switch (m_orderBy) {
            case BY_CU: {
                for (auto cu : e.getCUs()) {
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
            case BY_PC: {
                auto [entry, stack] = e.findByAddress(strtoul(m_pc.c_str(), nullptr, 16));
                if (entry.valid()) ImGui::Text(entry.get_description().c_str());
                for (auto& d : stack) {
                    dumpTree(d, e);
                }
                break;
            }
            case BY_LINETABLE: {
                for (auto cu : e.getCUs()) {
                    std::string name = "[UNKNOWN]";
                    auto& r = cu.root();
                    for (auto& attr : r.attributes()) {
                        if (attr.first == dwarf::DW_AT::name) {
                            name = to_string(attr.second);
                            break;
                        }
                    }
                    if (ImGui::TreeNode(name.c_str())) {
                        auto& lt = cu.get_line_table();
                        std::multimap<uint64_t, dwarf::line_table::entry> m;
                        for (auto& l : lt) {
                            uint64_t index = l.line;
                            index <<= 32;
                            index |= l.discriminator;
                            m.insert(std::pair(index, l));
                        }
                        for (auto& e : m) {
                            auto& l = e.second;
                            ImGui::Text(
                                ":%5i/%3i [%08lx] idx: %i, stmt: %i, basic: %i, endseq: %i, prlgend: %i, eplgend: %i, "
                                "discr: %i",
                                l.line, l.column, l.address, l.op_index, l.is_stmt, l.basic_block, l.end_sequence,
                                l.prologue_end, l.epilogue_begin, l.discriminator);
                        }
                        ImGui::TreePop();
                    }
                }
            }
        }
    }
    ImGui::EndChild();

    ImGui::End();
}
