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
#include <cstring>
#include <fstream>
#include <unordered_set>
#include <vector>

#include "core/psxemulator.h"
#include "core/system.h"
#include "fmt/format.h"
#include "imgui/imgui_internal.h"
#include "imgui_stdlib.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"
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

// Reads a fixed layout of fields out of its input, starting at an offset. The
// output carries the bytes of the field picked in the list.
struct StructNode : public PCSX::Widgets::Dalos::Node {
    enum Type { U8, S8, U16, S16, U32, S32, U64, S64, F32, F64, Chars, TypeCount };
    static constexpr const char* c_typeNames[TypeCount] = {"u8",  "s8",  "u16", "s16", "u32", "s32",
                                                           "u64", "s64", "f32", "f64", "char"};
    static constexpr unsigned c_typeSizes[TypeCount] = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 1};
    struct Field {
        std::string name;
        int type = U32;
        int count = 1;
    };
    std::vector<Field> m_fields = {{"field", U32, 1}};
    uint64_t m_offset = 0;
    int m_picked = -1;
    bool m_editing = false;

    StructNode() { m_inputs.resize(1); }
    unsigned inputs() override { return 1; }
    unsigned outputs() override { return 1; }
    const char* kind() override { return "Struct"; }

    static size_t fieldSize(const Field& f) { return size_t(c_typeSizes[f.type]) * size_t(std::max(f.count, 1)); }
    size_t fieldOffset(unsigned idx) {
        size_t offset = 0;
        for (unsigned i = 0; i < idx; i++) offset += fieldSize(m_fields[i]);
        return offset;
    }
    size_t structSize() { return fieldOffset(m_fields.size()); }

    PCSX::IO<PCSX::File> computeOutput(PCSX::Widgets::Dalos& dalos, unsigned) override {
        if (m_picked < 0 || m_picked >= int(m_fields.size())) return {};
        auto in = input(dalos, 0);
        if (!in) return {};
        size_t total = in->size();
        size_t size = fieldSize(m_fields[m_picked]);
        if (m_offset > total || fieldOffset(m_picked) + size > total - m_offset) return {};
        size_t offset = m_offset + fieldOffset(m_picked);
        return PCSX::IO<PCSX::File>(new PCSX::SubFile(in, offset, size));
    }

    // The PS1 is little endian, and so is everything this reads.
    static uint64_t readLE(const uint8_t* p, unsigned size) {
        uint64_t v = 0;
        for (unsigned i = 0; i < size; i++) v |= uint64_t(p[i]) << (i * 8);
        return v;
    }
    static std::string formatOne(const uint8_t* p, int type) {
        uint64_t v = readLE(p, c_typeSizes[type]);
        switch (type) {
            case U8:
            case U16:
            case U32:
                return fmt::format("{} (0x{:x})", v, v);
            case U64:
                return fmt::format("0x{:x}", v);
            case S8:
                return fmt::format("{}", int8_t(v));
            case S16:
                return fmt::format("{}", int16_t(v));
            case S32:
                return fmt::format("{}", int32_t(v));
            case S64:
                return fmt::format("{}", int64_t(v));
            case F32: {
                uint32_t bits = uint32_t(v);
                float f;
                memcpy(&f, &bits, sizeof(f));
                return fmt::format("{}", f);
            }
            case F64: {
                double d;
                memcpy(&d, &v, sizeof(d));
                return fmt::format("{}", d);
            }
        }
        return {};
    }
    static std::string formatField(const uint8_t* p, const Field& f) {
        if (f.type == Chars) {
            std::string str;
            for (int i = 0; i < f.count && p[i]; i++) str += (p[i] >= 32 && p[i] < 127) ? char(p[i]) : '.';
            return fmt::format("\"{}\"", str);
        }
        if (f.count <= 1) return formatOne(p, f.type);
        std::string str = "[";
        constexpr int c_shown = 4;
        for (int i = 0; i < std::min(f.count, c_shown); i++) {
            if (i) str += ", ";
            str += formatOne(p + i * c_typeSizes[f.type], f.type);
        }
        if (f.count > c_shown) str += ", ...";
        return str + "]";
    }

    bool body(PCSX::Widgets::Dalos& dalos) override {
        bool changed = ImGui::InputScalar(_("Offset (hex)"), ImGuiDataType_U64, &m_offset, nullptr, nullptr, "%llx",
                                          ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::Checkbox(_("Edit fields"), &m_editing);
        if (m_editing) {
            int toRemove = -1;
            for (unsigned i = 0; i < m_fields.size(); i++) {
                auto& f = m_fields[i];
                ImGui::PushID(i);
                ImGui::SetNextItemWidth(c_bodyWidth * 0.4f);
                changed |= ImGui::InputText("##name", &f.name);
                ImGui::SameLine();
                ImGui::SetNextItemWidth(c_bodyWidth * 0.3f);
                changed |= ImGui::Combo("##type", &f.type, c_typeNames, TypeCount);
                ImGui::SameLine();
                ImGui::SetNextItemWidth(c_bodyWidth * 0.2f);
                if (ImGui::InputInt("##count", &f.count, 0)) {
                    f.count = std::clamp(f.count, 1, 65536);
                    changed = true;
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("x")) toRemove = i;
                ImGui::PopID();
            }
            if (toRemove >= 0) {
                m_fields.erase(m_fields.begin() + toRemove);
                if (m_picked == toRemove) {
                    m_picked = -1;
                } else if (m_picked > toRemove) {
                    m_picked--;
                }
                changed = true;
            }
            if (ImGui::Button(_("Add field"))) {
                m_fields.push_back({fmt::format("field{}", m_fields.size()), U32, 1});
                changed = true;
            }
            ImGui::TextUnformatted(_("A count above 1 makes an array; for char it is the string length."));
            return changed;
        }

        auto in = input(dalos, 0);
        std::vector<uint8_t> data(structSize());
        bool complete = in && in->readAt(data.data(), data.size(), m_offset) == ssize_t(data.size());
        if (!complete) ImGui::TextUnformatted(in ? _("The input is too short.") : _("No input"));
        for (unsigned i = 0; i < m_fields.size(); i++) {
            auto& f = m_fields[i];
            auto value = complete ? formatField(data.data() + fieldOffset(i), f) : std::string("-");
            auto label = fmt::format("{} {} = {}##{}", c_typeNames[f.type], f.name, value, i);
            if (ImGui::Selectable(label.c_str(), m_picked == int(i))) {
                m_picked = m_picked == int(i) ? -1 : int(i);
                changed = true;
            }
        }
        ImGui::Text(_("%zu bytes"), data.size());
        return changed;
    }

    nlohmann::json save() override {
        nlohmann::json fields = nlohmann::json::array();
        for (auto& f : m_fields)
            fields.push_back({{"name", f.name}, {"type", c_typeNames[f.type]}, {"count", f.count}});
        return {{"offset", m_offset}, {"fields", fields}};
    }
    void load(const nlohmann::json& j) override {
        m_offset = j.value("offset", uint64_t(0));
        m_fields.clear();
        m_picked = -1;
        if (!j.contains("fields") || !j["fields"].is_array()) return;
        for (auto& f : j["fields"]) {
            Field field;
            field.name = f.value("name", std::string("field"));
            auto type = f.value("type", std::string("u32"));
            for (int t = 0; t < TypeCount; t++) {
                if (type == c_typeNames[t]) field.type = t;
            }
            field.count = std::clamp(f.value("count", 1), 1, 65536);
            m_fields.push_back(field);
        }
    }
};

// Runs a piece of Lua over its input. The code gets the input as a File in
// `...` and returns a File, or a string that gets wrapped into a buffer.
struct LuaFilterNode : public PCSX::Widgets::Dalos::Node {
    std::string m_code =
        "-- The input file is the first argument. Return a File,\n"
        "-- or a string, which becomes a buffer.\n"
        "local input = ...\n"
        "return input\n";
    PCSX::IO<PCSX::File> m_output;
    std::string m_error;
    bool m_ran = false;

    LuaFilterNode() { m_inputs.resize(1); }
    unsigned inputs() override { return 1; }
    unsigned outputs() override { return 1; }
    const char* kind() override { return "Lua filter"; }

    PCSX::IO<PCSX::File> computeOutput(PCSX::Widgets::Dalos& dalos, unsigned) override {
        if (!m_ran) run(dalos);
        return share(m_output);
    }

    void run(PCSX::Widgets::Dalos& dalos) {
        m_ran = true;
        m_output = {};
        m_error.clear();
        if (!PCSX::g_emulator->m_lua) {
            m_error = _("Lua is not available.");
            return;
        }
        auto in = input(dalos, 0);
        auto L = *PCSX::g_emulator->m_lua;
        int top = L.gettop();
        try {
            // The user code runs under its own pcall, so its errors come back
            // as a message for the node instead of going to the console.
            L.load(R"(
local code, raw = ...
local input
if raw then input = Support.File._createFileWrapper(ffi.cast('LuaFile*', raw)) end
local fn, err = loadstring(code, '=Dalos Lua filter')
if not fn then return false, err end
local ok, out = pcall(fn, input)
if not ok then return false, tostring(out) end
if type(out) == 'string' then
    local buf = Support.File.buffer()
    buf:write(out)
    out = buf
end
if type(out) ~= 'table' or out._type ~= 'File' or not ffi.istype('LuaFile*', out._wrapper) then return false, 'the filter returned neither a File nor a string' end
return true, out
)",
                   "internal:dalos-luafilter.lua", false);
            L.push(std::string_view(m_code));
            if (in) {
                L.push(static_cast<void*>(new PCSX::LuaFFI::LuaFile(in)));
            } else {
                L.push();
            }
            L.pcall(2);
            if (L.toboolean(top + 1)) {
                L.getfield("_wrapper", top + 2);
                m_output = (*L.topointer<PCSX::LuaFFI::LuaFile*>(-1))->file;
            } else {
                auto err = L.tostring(top + 2);
                m_error = err.empty() ? std::string(_("The filter failed.")) : err;
            }
        } catch (...) {
            m_error = _("The filter failed, see the Lua console.");
        }
        while (L.gettop() > top) L.pop();
    }

    bool body(PCSX::Widgets::Dalos& dalos) override {
        bool changed =
            ImGui::InputTextMultiline("##code", &m_code, ImVec2(c_bodyWidth * 1.6f, ImGui::GetTextLineHeight() * 8));
        if (ImGui::Button(_("Run"))) {
            run(dalos);
            changed = true;
        }
        if (!m_error.empty()) {
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + c_bodyWidth * 1.6f);
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", m_error.c_str());
            ImGui::PopTextWrapPos();
        } else if (m_output) {
            ImGui::Text(_("%zu bytes"), m_output->size());
        }
        return changed;
    }

    nlohmann::json save() override { return {{"code", m_code}}; }
    void load(const nlohmann::json& j) override {
        m_code = j.value("code", m_code);
        m_ran = false;
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
    if (m_saving == node) m_saving = nullptr;
    std::erase_if(m_nodes, [node](auto& n) { return n.get() == node; });
}

PCSX::Widgets::Dalos::Node* PCSX::Widgets::Dalos::addNodeOfKind(std::string_view kind, const std::string& name,
                                                                ImVec2 pos) {
    if (kind == "Struct") return addNode<StructNode>(name, pos);
    if (kind == "Lua filter") return addNode<LuaFilterNode>(name, pos);
    return nullptr;
}

void PCSX::Widgets::Dalos::loadSavedTypes() {
    if (m_savedTypesLoaded) return;
    m_savedTypesLoaded = true;
    std::ifstream in(g_system->getPersistentDir() / "dalos.json");
    if (!in) return;
    auto j = nlohmann::json::parse(in, nullptr, false);
    if (j.is_discarded() || !j.contains("nodes") || !j["nodes"].is_array()) return;
    for (auto& n : j["nodes"]) {
        if (!n.is_object() || !n["kind"].is_string() || !n["name"].is_string()) continue;
        auto data = n.contains("data") && n["data"].is_object() ? n["data"] : nlohmann::json::object();
        m_savedTypes.push_back({n["kind"].get<std::string>(), n["name"].get<std::string>(), data});
    }
}

void PCSX::Widgets::Dalos::writeSavedTypes() {
    nlohmann::json nodes = nlohmann::json::array();
    for (auto& t : m_savedTypes) nodes.push_back({{"kind", t.kind}, {"name", t.name}, {"data", t.data}});
    std::ofstream out(g_system->getPersistentDir() / "dalos.json");
    out << nlohmann::json{{"nodes", nodes}}.dump(4);
}

// True if `target` is `from` or feeds into it. Linking `from` into `target`
// would then close a loop, so the canvas refuses it.
bool PCSX::Widgets::Dalos::reaches(Node* from, Node* target) {
    std::vector<Node*> stack = {from};
    std::unordered_set<Node*> seen;
    while (!stack.empty()) {
        auto node = stack.back();
        stack.pop_back();
        if (node == target) return true;
        if (!seen.insert(node).second) continue;
        for (auto& link : node->m_inputs) {
            if (link.node) stack.push_back(link.node);
        }
    }
    return false;
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
        return;
    }

    ImGui::BeginChild("canvas", ImVec2(0, 0), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoMove);
    auto* dl = ImGui::GetWindowDrawList();
    auto canvasMin = ImGui::GetCursorScreenPos();
    auto canvasSize = ImGui::GetContentRegionAvail();
    m_origin = canvasMin + m_scroll;

    drawBackground(canvasMin, canvasSize);
    drawAddMenu();
    dl->PushClipRect(canvasMin, canvasMin + canvasSize, true);
    drawGrid(dl, canvasMin, canvasSize);

    // Channel 0 holds the links, 1 the node frames, 2 the node contents.
    dl->ChannelsSplit(3);
    Node* toDelete = nullptr;
    bool released = ImGui::IsMouseReleased(ImGuiMouseButton_Left);
    for (auto& node : m_nodes) {
        if (drawNode(dl, node.get(), released)) toDelete = node.get();
    }
    dl->ChannelsSetCurrent(0);
    drawLinks(dl);
    dl->ChannelsMerge();
    dl->PopClipRect();

    if (released) m_dragging = {};
    if (m_selected && ImGui::IsWindowFocused() && ImGui::IsKeyPressed(ImGuiKey_Delete) &&
        !ImGui::GetIO().WantTextInput) {
        toDelete = m_selected;
    }
    if (toDelete) deleteNode(toDelete);
    drawSavePopup();

    ImGui::EndChild();
    ImGui::End();
}

// An InvisibleButton covering the whole canvas catches clicks that miss every
// node, for panning and the context menu.
void PCSX::Widgets::Dalos::drawBackground(ImVec2 canvasMin, ImVec2 canvasSize) {
    ImGui::SetNextItemAllowOverlap();
    ImGui::InvisibleButton(
        "background", canvasSize,
        ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight | ImGuiButtonFlags_MouseButtonMiddle);
    if (ImGui::IsItemActive() && anyMouseDragging()) {
        m_scroll += ImGui::GetIO().MouseDelta;
        m_origin = canvasMin + m_scroll;
    }
    if (!ImGui::IsItemHovered()) return;
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) m_selected = nullptr;
    if (rightClickedInPlace()) {
        m_popupPos = ImGui::GetIO().MousePos - m_origin;
        ImGui::OpenPopup("add");
    }
}

bool PCSX::Widgets::Dalos::anyMouseDragging() {
    return ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f) ||
           ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f) || ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f);
}

// A right click that did not drag, which is what opens the add menu.
bool PCSX::Widgets::Dalos::rightClickedInPlace() {
    auto drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Right);
    return ImGui::IsMouseReleased(ImGuiMouseButton_Right) && drag.x == 0.0f && drag.y == 0.0f;
}

void PCSX::Widgets::Dalos::drawAddMenu() {
    if (!ImGui::BeginPopup("add")) return;
    ImGui::TextDisabled("%s", _("Add node"));
    ImGui::Separator();
    if (ImGui::MenuItem(_("File"))) addNode<FileNode>(_("File"), m_popupPos);
    if (ImGui::MenuItem(_("Slice"))) addNode<SliceNode>(_("Slice"), m_popupPos);
    if (ImGui::MenuItem(_("Viewer"))) addNode<ViewerNode>(_("Viewer"), m_popupPos);
    if (ImGui::MenuItem(_("Struct"))) addNode<StructNode>(_("Struct"), m_popupPos);
    if (ImGui::MenuItem(_("Lua filter"))) addNode<LuaFilterNode>(_("Lua filter"), m_popupPos);
    drawSavedTypesMenu();
    ImGui::EndPopup();
}

void PCSX::Widgets::Dalos::drawSavedTypesMenu() {
    loadSavedTypes();
    if (m_savedTypes.empty()) return;
    ImGui::Separator();
    for (auto& type : m_savedTypes) {
        auto label = fmt::format("{}: {}", type.kind, type.name);
        if (!ImGui::MenuItem(label.c_str())) continue;
        auto node = addNodeOfKind(type.kind, type.name, m_popupPos);
        if (!node) continue;
        // A hand-edited dalos.json can hold values of the wrong type.
        try {
            node->load(type.data);
        } catch (const nlohmann::json::exception&) {
        }
    }
    if (!ImGui::BeginMenu(_("Forget a saved node"))) return;
    int toForget = -1;
    for (unsigned i = 0; i < m_savedTypes.size(); i++) {
        auto label = fmt::format("{}: {}", m_savedTypes[i].kind, m_savedTypes[i].name);
        if (ImGui::MenuItem(label.c_str())) toForget = i;
    }
    if (toForget >= 0) {
        m_savedTypes.erase(m_savedTypes.begin() + toForget);
        writeSavedTypes();
    }
    ImGui::EndMenu();
}

// The modal behind a node's "Save as a new node..." entry.
void PCSX::Widgets::Dalos::drawSavePopup() {
    if (m_saving && !ImGui::IsPopupOpen("save")) ImGui::OpenPopup("save");
    if (!ImGui::BeginPopupModal("save", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::TextUnformatted(_("Save this node's setup under a name. It then shows up in the add menu."));
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    bool save = ImGui::InputText(_("Name"), &m_savingName, ImGuiInputTextFlags_EnterReturnsTrue);
    save |= ImGui::Button(_("Save"));
    ImGui::SameLine();
    bool done = ImGui::Button(_("Cancel")) || !m_saving;
    if (save && m_saving && !m_savingName.empty()) {
        std::string kind = m_saving->kind();
        std::erase_if(m_savedTypes, [&](auto& t) { return t.kind == kind && t.name == m_savingName; });
        m_savedTypes.push_back({kind, m_savingName, m_saving->save()});
        writeSavedTypes();
        done = true;
    }
    if (done) {
        m_saving = nullptr;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void PCSX::Widgets::Dalos::drawGrid(ImDrawList* dl, ImVec2 canvasMin, ImVec2 canvasSize) {
    constexpr float c_grid = 64.0f;
    auto canvasMax = canvasMin + canvasSize;
    for (float x = std::fmod(m_scroll.x, c_grid); x < canvasSize.x; x += c_grid) {
        dl->AddLine(ImVec2(canvasMin.x + x, canvasMin.y), ImVec2(canvasMin.x + x, canvasMax.y),
                    IM_COL32(200, 200, 200, 40));
    }
    for (float y = std::fmod(m_scroll.y, c_grid); y < canvasSize.y; y += c_grid) {
        dl->AddLine(ImVec2(canvasMin.x, canvasMin.y + y), ImVec2(canvasMax.x, canvasMin.y + y),
                    IM_COL32(200, 200, 200, 40));
    }
}

// Draws one node and its pins. Returns true if the user asked to delete it.
bool PCSX::Widgets::Dalos::drawNode(ImDrawList* dl, Node* node, bool released) {
    auto& io = ImGui::GetIO();
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
    if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) node->m_pos += io.MouseDelta;
    bool remove = false;
    if (ImGui::BeginPopupContextItem("node")) {
        if (node->kind() && ImGui::MenuItem(_("Save as a new node..."))) {
            m_saving = node;
            m_savingName = node->m_name;
        }
        remove = ImGui::MenuItem(_("Delete"));
        ImGui::EndPopup();
    }

    dl->ChannelsSetCurrent(1);
    bool selected = m_selected == node;
    dl->AddRectFilled(pos, pos + node->m_size, IM_COL32(50, 50, 55, 240), 4.0f);
    dl->AddRectFilled(pos, pos + ImVec2(node->m_size.x, titleHeight), IM_COL32(70, 90, 120, 255), 4.0f,
                      ImDrawFlags_RoundCornersTop);
    dl->AddRect(pos, pos + node->m_size, selected ? IM_COL32(255, 200, 80, 255) : IM_COL32(100, 100, 100, 255), 4.0f, 0,
                selected ? 2.0f : 1.0f);
    drawOutputPins(dl, node);
    drawInputPins(dl, node, released);
    ImGui::PopID();
    return remove;
}

// Output pins start a link.
void PCSX::Widgets::Dalos::drawOutputPins(ImDrawList* dl, Node* node) {
    const auto pinSize = ImVec2(c_pinRadius * 4, c_pinRadius * 4);
    for (unsigned i = 0; i < node->outputs(); i++) {
        auto p = outputPinPos(node, i);
        ImGui::SetCursorScreenPos(p - pinSize * 0.5f);
        ImGui::PushID(1000 + i);
        ImGui::InvisibleButton("out", pinSize);
        if (ImGui::IsItemActive() && !m_dragging.node) m_dragging = {node, i};
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopID();
        dl->AddCircleFilled(p, c_pinRadius, hovered ? IM_COL32(255, 200, 80, 255) : IM_COL32(180, 220, 180, 255));
    }
}

// Input pins end a link, and right-clicking one cuts its link.
void PCSX::Widgets::Dalos::drawInputPins(ImDrawList* dl, Node* node, bool released) {
    const auto pinSize = ImVec2(c_pinRadius * 4, c_pinRadius * 4);
    for (unsigned i = 0; i < node->inputs(); i++) {
        auto p = inputPinPos(node, i);
        ImGui::SetCursorScreenPos(p - pinSize * 0.5f);
        ImGui::PushID(2000 + i);
        ImGui::InvisibleButton("in", pinSize, ImGuiButtonFlags_MouseButtonRight);
        bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) node->m_inputs[i] = {};
        ImGui::PopID();
        if (hovered && released) dropLink(node, i);
        dl->AddCircleFilled(p, c_pinRadius, hovered ? IM_COL32(255, 200, 80, 255) : IM_COL32(180, 180, 220, 255));
    }
}

// Connects the link being dragged to `node`'s input `pin`, unless it would
// close a loop.
void PCSX::Widgets::Dalos::dropLink(Node* node, unsigned pin) {
    if (m_dragging.node && !reaches(m_dragging.node, node)) node->m_inputs[pin] = m_dragging;
}

void PCSX::Widgets::Dalos::drawLinks(ImDrawList* dl) {
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
    if (m_dragging.node) bezier(outputPinPos(m_dragging.node, m_dragging.pin), ImGui::GetIO().MousePos);
}
