/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "gui/widgets/zep.h"

#include <GLFW/glfw3.h>

void PCSX::Widgets::ZepEditor::draw() {
    auto dpiScale = ImGui::GetWindowDpiScale();
    auto min = ImGui::GetCursorScreenPos();
    auto max = ImGui::GetContentRegionAvail();
    max.x = std::max(1.0f, max.x);
    max.y = std::max(1.0f, max.y);

    // Fill the window
    max.x = min.x + max.x;
    max.y = min.y + max.y;
    m_editor->SetDisplayRegion(Zep::NVec2f(min.x, min.y), Zep::NVec2f(max.x, max.y));

    // Display the editor inside this window
    m_editor->Display();
    auto& io = ImGui::GetIO();

    if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0) {
        m_editor->OnMouseMove(Zep::toNVec2f(io.MousePos));
    }

    if (io.MouseClicked[0]) {
        if (m_editor->OnMouseDown(Zep::toNVec2f(io.MousePos), Zep::ZepMouseButton::Left)) {
            // Hide the mouse click from imgui if we handled it
            io.MouseClicked[0] = false;
        }
    }

    if (io.MouseClicked[1]) {
        if (m_editor->OnMouseDown(Zep::toNVec2f(io.MousePos), Zep::ZepMouseButton::Right)) {
            // Hide the mouse click from imgui if we handled it
            io.MouseClicked[0] = false;
        }
    }

    if (io.MouseReleased[0]) {
        if (m_editor->OnMouseUp(Zep::toNVec2f(io.MousePos), Zep::ZepMouseButton::Left)) {
            // Hide the mouse click from imgui if we handled it
            io.MouseClicked[0] = false;
        }
    }

    if (io.MouseReleased[1]) {
        if (m_editor->OnMouseUp(Zep::toNVec2f(io.MousePos), Zep::ZepMouseButton::Right)) {
            // Hide the mouse click from imgui if we handled it
            io.MouseClicked[0] = false;
        }
    }

    if (ImGui::IsWindowFocused()) {
        bool handled = false;

        uint32_t mod = 0;

        static std::map<int, int> MapUSBKeys = {
            {GLFW_KEY_F1, Zep::ExtKeys::F1},   {GLFW_KEY_F2, Zep::ExtKeys::F2},   {GLFW_KEY_F3, Zep::ExtKeys::F3},
            {GLFW_KEY_F4, Zep::ExtKeys::F4},   {GLFW_KEY_F5, Zep::ExtKeys::F5},   {GLFW_KEY_F6, Zep::ExtKeys::F6},
            {GLFW_KEY_F7, Zep::ExtKeys::F7},   {GLFW_KEY_F8, Zep::ExtKeys::F8},   {GLFW_KEY_F9, Zep::ExtKeys::F9},
            {GLFW_KEY_F10, Zep::ExtKeys::F10}, {GLFW_KEY_F11, Zep::ExtKeys::F11}, {GLFW_KEY_F12, Zep::ExtKeys::F12},
        };

        if (io.KeyCtrl) {
            mod |= Zep::ModifierKey::Ctrl;
        }
        if (io.KeyShift) {
            mod |= Zep::ModifierKey::Shift;
        }

        auto pWindow = m_editor->GetActiveTabWindow()->GetActiveWindow();
        const auto& buffer = pWindow->GetBuffer();

        // Check USB Keys
        for (auto& usbKey : MapUSBKeys) {
            if (ImGui::IsKeyPressed(usbKey.first)) {
                buffer.GetMode()->AddKeyPress(usbKey.second, mod);
                return;
            }
        }

        if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Tab))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::TAB, mod);
            return;
        }
        if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Escape))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::ESCAPE, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Enter))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::RETURN, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Delete))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::DEL, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Home))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::HOME, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_End))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::END, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_Backspace))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::BACKSPACE, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_RightArrow))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::RIGHT, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_LeftArrow))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::LEFT, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_UpArrow))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::UP, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_DownArrow))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::DOWN, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_PageDown))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::PAGEDOWN, mod);
            return;
        } else if (ImGui::IsKeyPressed(ImGui::GetKeyIndex(ImGuiKey_PageUp))) {
            buffer.GetMode()->AddKeyPress(Zep::ExtKeys::PAGEUP, mod);
            return;
        } else if (io.KeyCtrl) {
            if (ImGui::IsKeyPressed('1')) {
                m_editor->SetGlobalMode(Zep::ZepMode_Standard::StaticName());
                handled = true;
            } else if (ImGui::IsKeyPressed('2')) {
                m_editor->SetGlobalMode(Zep::ZepMode_Vim::StaticName());
                handled = true;
            } else {
                for (int ch = 'A'; ch <= 'Z'; ch++) {
                    if (ImGui::IsKeyPressed(ch)) {
                        buffer.GetMode()->AddKeyPress(ch - 'A' + 'a', mod);
                        handled = true;
                    }
                }

                if (ImGui::IsKeyPressed(GLFW_KEY_SPACE)) {
                    buffer.GetMode()->AddKeyPress(' ', mod);
                    handled = true;
                }
            }
        }

        if (!handled) {
            for (int n = 0; n < io.InputQueueCharacters.Size && io.InputQueueCharacters[n]; n++) {
                // Ignore '\r' - sometimes ImGui generates it!
                if (io.InputQueueCharacters[n] == '\r') continue;

                buffer.GetMode()->AddKeyPress(io.InputQueueCharacters[n], mod);
            }
        }
    }
}
