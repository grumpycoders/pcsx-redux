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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "gui/widgets/fileviewers.h"
#include "imgui/imgui.h"
#include "support/file.h"

namespace PCSX {
namespace Widgets {

// Dalos is a canvas of nodes wired together. Every link carries a File: sources
// produce one, filters derive a new one from their inputs, and sinks consume
// them. Evaluation is lazy: a node computes its output only when something
// downstream asks for it.
class Dalos {
  public:
    Dalos(bool& show) : m_show(show) {}
    void draw(const char* title);
    // Adds a source node holding `file`, e.g. an entry picked in the ISO browser.
    void addSource(const std::string& name, IO<File> file);

    bool& m_show;

    struct Node;
    struct Link {
        Node* node = nullptr;
        unsigned pin = 0;
    };
    struct Node {
        virtual ~Node() = default;
        virtual unsigned inputs() { return 0; }
        virtual unsigned outputs() { return 0; }
        virtual IO<File> computeOutput(Dalos&, unsigned pin) { return {}; }
        // Draws the node's settings. Returns true if anything changed.
        virtual bool body(Dalos&) { return false; }

        IO<File> output(Dalos&, unsigned pin);
        IO<File> input(Dalos&, unsigned pin);

        std::string m_name;
        ImVec2 m_pos;
        ImVec2 m_size = {0, 0};
        unsigned m_id = 0;
        std::vector<Link> m_inputs;
        bool m_evaluating = false;
    };

    FileViewers& fileViewers() { return m_fileViewers; }

  private:
    template <typename T>
    T* addNode(const std::string& name, ImVec2 pos);
    void deleteNode(Node* node);
    ImVec2 inputPinPos(Node* node, unsigned pin);
    ImVec2 outputPinPos(Node* node, unsigned pin);

    std::vector<std::unique_ptr<Node>> m_nodes;
    FileViewers m_fileViewers;
    ImVec2 m_scroll = {0, 0};
    ImVec2 m_origin;
    unsigned m_nextId = 1;
    Node* m_selected = nullptr;
    Link m_dragging;
    ImVec2 m_popupPos;
    bool m_focus = false;
};

}  // namespace Widgets
}  // namespace PCSX
