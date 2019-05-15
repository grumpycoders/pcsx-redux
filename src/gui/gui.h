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

#include "flags.h"

#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

#include "gui/widgets/assembly.h"
#include "gui/widgets/breakpoints.h"
#include "gui/widgets/filedialog.h"
#include "gui/widgets/log.h"
#include "gui/widgets/registers.h"

namespace PCSX {

class GUI final {
  public:
    GUI(const flags::args &args) : m_args(args) {}
    void init();
    void close();
    void update();
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
        // SDL_TriggerBreakpoint();
    }
    void scheduleSoftReset() { m_scheduleSoftReset = true; }
    void scheduleHardReset() { m_scheduleHardReset = true; }

  private:
    static void checkGL();
    void saveCfg();

    void startFrame();
    void endFrame();

    bool configure();

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
    int m_currentTexture = -1;

    ImVec4 m_backgroundColor = ImColor(114, 144, 154);
    ImVec2 m_renderSize = ImVec2(1, 1);

    float m_renderRatio = 3.0f / 4.0f;
    bool m_fullscreen = false;

    // GUI
    bool m_fullscreenRender = true;
    bool m_showMenu = false;
    bool m_showDemo = false;
    bool m_showVRAMwindow = false;
    bool m_showAbout = false;
    Widgets::Log m_log;
    struct MemoryEditorWrapper {
        MemoryEditorWrapper() {
            editor.OptShowDataPreview = true;
            editor.OptUpperCaseHex = false;
        }
        MemoryEditor editor;
        std::string title;
        bool &show = editor.Open;
        void MenuItem() { ImGui::MenuItem(title.c_str(), nullptr, &show); }
        void draw(void *mem, size_t size, uint32_t baseAddr = 0) {
            editor.DrawWindow(title.c_str(), mem, size, baseAddr);
        }
    };
    MemoryEditorWrapper m_mainMemEditors[8];
    MemoryEditorWrapper m_parallelPortEditor;
    MemoryEditorWrapper m_scratchPadEditor;
    MemoryEditorWrapper m_hwrEditor;
    MemoryEditorWrapper m_biosEditor;
    Widgets::Registers m_registers;
    Widgets::Assembly m_assembly = {&m_mainMemEditors[0].editor, &m_hwrEditor.editor};
    Widgets::FileDialog m_openIsoFileDialog = {"Open Image"};
    Widgets::FileDialog m_selectBiosDialog = {"Select BIOS"};
    Widgets::Breakpoints m_breakpoints;

    bool m_showCfg = false;

    const flags::args &m_args;
    bool m_scheduleSoftReset = false;
    bool m_scheduleHardReset = false;
};

}  // namespace PCSX
