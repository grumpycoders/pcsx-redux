/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#define IMGUI_DEFINE_MATH_OPERATORS
#include "gui/widgets/dalos.h"

#include <algorithm>
#include <cmath>

#include "core/system.h"
#include "fmt/format.h"
#include "imgui/imgui_internal.h"
#include "imgui_stdlib.h"
#include "support/imgui-helpers.h"

namespace {

constexpr float c_padding = 8.0f;
constexpr float c_pinRadius = 5.0f;
constexpr float c_bodyWidth = 180.0f;

// Every node hands out a SubFile over what it holds, so a consumer closing its
// file does not close the node's own copy.
PCSX::IO<PCSX::File> share(PCSX::IO<PCSX::File> file) {
    if (!file || file->failed()) return {};
    return PCSX::IO<PCSX::File>(new PCSX::SubFile(file, 0, file->size()));
}

struct HandleNode : public PCSX::Widgets::Dalos::Node {
    PCSX::IO<PCSX::File> m_file;
    unsigned outputs() override { return 1; }
    PCSX::IO<PCSX::File> computeOutput(PCSX::Widgets::Dalos&, unsigned) override { return share(m_file); }
    bool body(PCSX::Widgets::Dalos&) override {
        ImGui::Text(_("%zu bytes"), m_file ? m_file->size() : size_t(0));
        return false;
    }
};

struct FileNode : public PCSX::Widgets::Dalos::Node {
    std::string m_path;
    PCSX::IO<PCSX::File> m_file;
    unsigned outputs() override { return 1; }
    PCSX::IO<PCSX::File> computeOutput(PCSX::Widgets::Dalos&, unsigned) override { return share(m_file); }
    bool body(PCSX::Widgets::Dalos&) override {
        bool changed = ImGui::InputText(_("Path"), &m_path, ImGuiInputTextFlags_EnterReturnsTrue);
        if (changed) {
            m_file = m_path.empty() ? PCSX::IO<PCSX::File>() : PCSX::IO<PCSX::File>(new PCSX::PosixFile(m_path));
        }
        if (!m_file) {
            ImGui::TextUnformatted(_("No file"));
        } else if (m_file->failed()) {
            ImGui::TextUnformatted(_("Unable to open"));
        } else {
            ImGui::Text(_("%zu bytes"), m_file->size());
        }
        return changed;
    }
};

struct SliceNode : public PCSX::Widgets::Dalos::Node {
    SliceNode() { m_inputs.resize(1); }
    uint64_t m_offset = 0;
    int64_t m_size = -1;
    unsigned inputs() override { return 1; }
    unsigned outputs() override { return 1; }
    PCSX::IO<PCSX::File> computeOutput(PCSX::Widgets::Dalos& dalos, unsigned) override {
        auto in = input(dalos, 0);
        if (!in) return {};
        size_t total = in->size();
        if (m_offset > total) return {};
        size_t size = total - m_offset;
        if (m_size >= 0) size = std::min(size, size_t(m_size));
        return PCSX::IO<PCSX::File>(new PCSX::SubFile(in, m_offset, size));
    }
    bool body(PCSX::Widgets::Dalos&) override {
        bool changed = ImGui::InputScalar(_("Offset (hex)"), ImGuiDataType_U64, &m_offset, nullptr, nullptr, "%llx",
                                          ImGuiInputTextFlags_CharsHexadecimal);
        changed |= ImGui::InputScalar(_("Size"), ImGuiDataType_S64, &m_size);
        ImGui::TextUnformatted(_("A size of -1 takes the rest."));
        return changed;
    }
};

struct ViewerNode : public PCSX::Widgets::Dalos::Node {
    ViewerNode() { m_inputs.resize(1); }
    unsigned inputs() override { return 1; }
    bool body(PCSX::Widgets::Dalos& dalos) override {
        auto in = input(dalos, 0);
        if (!dalos.fileViewers().available()) {
            ImGui::TextUnformatted(_("fileviewers.lua is not loaded"));
            return false;
        }
        ImGui::BeginDisabled(!in);
        if (ImGui::Button(_("Open viewer"))) dalos.fileViewers().open(m_name, in);
        ImGui::EndDisabled();
        if (in) ImGui::Text(_("%zu bytes"), in->size());
        return false;
    }
};

}  // namespace

PCSX::IO<PCSX::File> PCSX::Widgets::Dalos::Node::output(Dalos& dalos, unsigned pin) {
    // A loop in the graph evaluates to nothing instead of recursing forever.
    if (m_evaluating) return {};
    m_evaluating = true;
    auto ret = computeOutput(dalos, pin);
    m_evaluating = false;
    return ret;
}

PCSX::IO<PCSX::File> PCSX::Widgets::Dalos::Node::input(Dalos& dalos, unsigned pin) {
    if (pin >= m_inputs.size()) return {};
    auto& link = m_inputs[pin];
    if (!link.node) return {};
    return link.node->output(dalos, link.pin);
}

template <typename T>
T* PCSX::Widgets::Dalos::addNode(const std::string& name, ImVec2 pos) {
    auto node = new T();
    node->m_id = m_nextId++;
    node->m_name = fmt::format("{} {}", name, node->m_id);
    node->m_pos = pos;
    m_nodes.emplace_back(node);
    return node;
}

void PCSX::Widgets::Dalos::addSource(const std::string& name, IO<File> file) {
    // Drop new sources in a cascade near the top left of whatever is on screen.
    auto pos = ImVec2(40.0f, 40.0f) - m_scroll + ImVec2(float(m_nodes.size() % 8) * 20.0f, 0.0f);
    auto node = addNode<HandleNode>(name, pos);
    node->m_name = name;
    node->m_file = file;
    m_show = true;
    m_focus = true;
}

void PCSX::Widgets::Dalos::deleteNode(Node* node) {
    for (auto& n : m_nodes) {
        for (auto& link : n->m_inputs) {
            if (link.node == node) link = {};
        }
    }
    if (m_selected == node) m_selected = nullptr;
    if (m_dragging.node == node) m_dragging = {};
    std::erase_if(m_nodes, [node](auto& n) { return n.get() == node; });
}

ImVec2 PCSX::Widgets::Dalos::inputPinPos(Node* node, unsigned pin) {
    auto pos = m_origin + node->m_pos;
    return ImVec2(pos.x, pos.y + node->m_size.y * float(pin + 1) / float(node->inputs() + 1));
}

ImVec2 PCSX::Widgets::Dalos::outputPinPos(Node* node, unsigned pin) {
    auto pos = m_origin + node->m_pos;
    return ImVec2(pos.x + node->m_size.x, pos.y + node->m_size.y * float(pin + 1) / float(node->outputs() + 1));
}

void PCSX::Widgets::Dalos::draw(const char* title) {
    ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver);
    if (m_focus) {
        ImGui::SetNextWindowFocus();
        m_focus = false;
    }
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        m_fileViewers.draw();
        return;
    }

    ImGui::BeginChild("canvas", ImVec2(0, 0), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoMove);
    auto& io = ImGui::GetIO();
    auto* dl = ImGui::GetWindowDrawList();
    auto canvasMin = ImGui::GetCursorScreenPos();
    auto canvasSize = ImGui::GetContentRegionAvail();
    auto canvasMax = canvasMin + canvasSize;
    m_origin = canvasMin + m_scroll;

    // Background: an InvisibleButton covering the whole canvas catches clicks
    // that miss every node, for panning and the context menu.
    ImGui::SetNextItemAllowOverlap();
    ImGui::InvisibleButton(
        "background", canvasSize,
        ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight | ImGuiButtonFlags_MouseButtonMiddle);
    bool backgroundHovered = ImGui::IsItemHovered();
    if (ImGui::IsItemActive() && (ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f) ||
                                  ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f) ||
                                  ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f))) {
        m_scroll += io.MouseDelta;
        m_origin = canvasMin + m_scroll;
    }
    if (backgroundHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) m_selected = nullptr;
    auto drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Right);
    if (backgroundHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right) && drag.x == 0.0f && drag.y == 0.0f) {
        m_popupPos = io.MousePos - m_origin;
        ImGui::OpenPopup("add");
    }
    if (ImGui::BeginPopup("add")) {
        ImGui::TextDisabled(_("Add node"));
        ImGui::Separator();
        if (ImGui::MenuItem(_("File"))) addNode<FileNode>(_("File"), m_popupPos);
        if (ImGui::MenuItem(_("Slice"))) addNode<SliceNode>(_("Slice"), m_popupPos);
        if (ImGui::MenuItem(_("Viewer"))) addNode<ViewerNode>(_("Viewer"), m_popupPos);
        ImGui::EndPopup();
    }

    dl->PushClipRect(canvasMin, canvasMax, true);
    constexpr float c_grid = 64.0f;
    for (float x = std::fmod(m_scroll.x, c_grid); x < canvasSize.x; x += c_grid) {
        dl->AddLine(ImVec2(canvasMin.x + x, canvasMin.y), ImVec2(canvasMin.x + x, canvasMax.y),
                    IM_COL32(200, 200, 200, 40));
    }
    for (float y = std::fmod(m_scroll.y, c_grid); y < canvasSize.y; y += c_grid) {
        dl->AddLine(ImVec2(canvasMin.x, canvasMin.y + y), ImVec2(canvasMax.x, canvasMin.y + y),
                    IM_COL32(200, 200, 200, 40));
    }

    // Channel 0 holds the links, 1 the node frames, 2 the node contents.
    dl->ChannelsSplit(3);
    Node* toDelete = nullptr;
    bool released = ImGui::IsMouseReleased(ImGuiMouseButton_Left);
    for (auto& nodePtr : m_nodes) {
        auto node = nodePtr.get();
        ImGui::PushID(node->m_id);
        auto pos = m_origin + node->m_pos;

        dl->ChannelsSetCurrent(2);
        ImGui::SetCursorScreenPos(pos + ImVec2(c_padding, c_padding));
        ImGui::BeginGroup();
        ImGui::TextUnformatted(node->m_name.c_str());
        float titleHeight = ImGui::GetItemRectSize().y + c_padding * 1.5f;
        ImGui::Dummy(ImVec2(c_bodyWidth, c_padding * 0.5f));
        ImGui::PushItemWidth(c_bodyWidth * 0.6f);
        node->body(*this);
        ImGui::PopItemWidth();
        ImGui::EndGroup();
        node->m_size = ImGui::GetItemRectSize() + ImVec2(c_padding * 2, c_padding * 2);

        // The title bar moves and selects the node.
        ImGui::SetCursorScreenPos(pos);
        ImGui::InvisibleButton("title", ImVec2(node->m_size.x, titleHeight));
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) m_selected = node;
        if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) {
            node->m_pos += io.MouseDelta;
        }
        if (ImGui::BeginPopupContextItem("node")) {
            if (ImGui::MenuItem(_("Delete"))) toDelete = node;
            ImGui::EndPopup();
        }

        dl->ChannelsSetCurrent(1);
        bool selected = m_selected == node;
        dl->AddRectFilled(pos, pos + node->m_size, IM_COL32(50, 50, 55, 240), 4.0f);
        dl->AddRectFilled(pos, pos + ImVec2(node->m_size.x, titleHeight), IM_COL32(70, 90, 120, 255), 4.0f,
                          ImDrawFlags_RoundCornersTop);
        dl->AddRect(pos, pos + node->m_size, selected ? IM_COL32(255, 200, 80, 255) : IM_COL32(100, 100, 100, 255),
                    4.0f, 0, selected ? 2.0f : 1.0f);

        // Output pins start a link, input pins end one. Right-clicking an
        // input pin cuts its link.
        for (unsigned i = 0; i < node->outputs(); i++) {
            auto p = outputPinPos(node, i);
            ImGui::SetCursorScreenPos(p - ImVec2(c_pinRadius * 2, c_pinRadius * 2));
            ImGui::PushID(1000 + i);
            ImGui::InvisibleButton("out", ImVec2(c_pinRadius * 4, c_pinRadius * 4));
            if (ImGui::IsItemActive() && !m_dragging.node) m_dragging = {node, i};
            bool hovered = ImGui::IsItemHovered();
            ImGui::PopID();
            dl->AddCircleFilled(p, c_pinRadius, hovered ? IM_COL32(255, 200, 80, 255) : IM_COL32(180, 220, 180, 255));
        }
        for (unsigned i = 0; i < node->inputs(); i++) {
            auto p = inputPinPos(node, i);
            ImGui::SetCursorScreenPos(p - ImVec2(c_pinRadius * 2, c_pinRadius * 2));
            ImGui::PushID(2000 + i);
            ImGui::InvisibleButton("in", ImVec2(c_pinRadius * 4, c_pinRadius * 4), ImGuiButtonFlags_MouseButtonRight);
            bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) node->m_inputs[i] = {};
            ImGui::PopID();
            if (hovered && released && m_dragging.node && m_dragging.node != node) node->m_inputs[i] = m_dragging;
            dl->AddCircleFilled(p, c_pinRadius, hovered ? IM_COL32(255, 200, 80, 255) : IM_COL32(180, 180, 220, 255));
        }
        ImGui::PopID();
    }

    dl->ChannelsSetCurrent(0);
    auto bezier = [dl](ImVec2 a, ImVec2 b) {
        float ctrl = std::max(40.0f, std::abs(b.x - a.x) * 0.5f);
        dl->AddBezierCubic(a, a + ImVec2(ctrl, 0), b - ImVec2(ctrl, 0), b, IM_COL32(220, 220, 220, 255), 2.0f);
    };
    for (auto& node : m_nodes) {
        for (unsigned i = 0; i < node->m_inputs.size(); i++) {
            auto& link = node->m_inputs[i];
            if (link.node) bezier(outputPinPos(link.node, link.pin), inputPinPos(node.get(), i));
        }
    }
    if (m_dragging.node) bezier(outputPinPos(m_dragging.node, m_dragging.pin), io.MousePos);
    dl->ChannelsMerge();
    dl->PopClipRect();

    if (released) m_dragging = {};
    if (m_selected && ImGui::IsWindowFocused() && ImGui::IsKeyPressed(ImGuiKey_Delete) &&
        !ImGui::GetIO().WantTextInput) {
        toDelete = m_selected;
    }
    if (toDelete) deleteNode(toDelete);

    ImGui::EndChild();
    ImGui::End();
    m_fileViewers.draw();
}
