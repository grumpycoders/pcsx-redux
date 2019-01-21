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

#pragma once

#include <SDL.h>
#include <stdarg.h>

#include <string>

#include "imgui.h"

#include "gui/widgets/log.h"
#include "gui/widgets/registers.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

namespace PCSX {

class GUI final {
  public:
    void init();
    void update() {
        endFrame();
        startFrame();
    }
    void flip();
    void bindVRAMTexture();
    void setViewport();
    void setFullscreen(bool);
    void addLog(const char *fmt, ...) {
        va_list args;
        va_start(args, fmt);
        addLog(fmt, args);
        va_end(args);
    }
    void addLog(const char *fmt, va_list args) { m_log.addLog(fmt, args); }
    void addNotification(const char *fmt, va_list args) {
        // TODO
        SDL_TriggerBreakpoint();
    }

  private:
    static void checkGL();

    void startFrame();
    void endFrame();

    void normalizeDimensions(ImVec2 &vec, float ratio) {
        float r = vec.y / vec.x;
        if (r > ratio) {
            vec.y = vec.x * ratio;
        } else {
            vec.x = vec.y / ratio;
        }
    }

    SDL_Window *m_window = nullptr;
    SDL_GLContext m_glContext = nullptr;
    unsigned int m_VRAMTexture = 0;

    unsigned int m_offscreenFrameBuffer = 0;
    unsigned int m_offscreenTextures[2] = {0, 0};
    unsigned int m_offscreenDepthBuffer = 0;
    int m_currentTexture;

    ImVec4 m_backgroundColor = ImColor(114, 144, 154);
    ImVec2 m_renderSize = ImVec2(1, 1);

    float m_renderRatio = 3.0f / 4.0f;
    bool m_fullscreen = false;

    // GUI
    bool m_fullscreenRender = true;
    bool m_showMenu = false;
    bool m_showDemo = false;
    bool m_showVRAMwindow = false;
    Widgets::Log m_log;
    struct MemoryEditorWrapper {
        MemoryEditor editor;
        std::string title;
        bool show;
    };
    MemoryEditorWrapper m_mainMemEditors[8];
    Widgets::Registers m_registers;
};

}  // namespace PCSX
