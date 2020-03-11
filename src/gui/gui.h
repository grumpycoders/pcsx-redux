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

#include <stdarg.h>

#include <string>

#include "flags.h"

#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

#include "core/system.h"
#include "gui/widgets/assembly.h"
#include "gui/widgets/breakpoints.h"
#include "gui/widgets/filedialog.h"
#include "gui/widgets/log.h"
#include "gui/widgets/registers.h"
#include "gui/widgets/vram-viewer.h"
#include "support/settings.h"

#if defined(__MACOSX__)
#define GL_SHADER_VERSION "#version 410\n"
#else
#define GL_SHADER_VERSION "#version 300 es\n"
#endif

struct GLFWwindow;

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

    static void checkGL();

  private:
    void saveCfg();

    void startFrame();
    void endFrame();

    bool configure();
    void biosCounters();
    void about();
    void interruptsScaler();

  public:
    static void normalizeDimensions(ImVec2 &vec, float ratio) {
        float r = vec.y / vec.x;
        if (r > ratio) {
            vec.y = vec.x * ratio;
        } else {
            vec.x = vec.y / ratio;
        }
    }

  private:
    GLFWwindow *m_window = nullptr;
    int &m_glfwPosX = settings.get<WindowPosX>().value;
    int &m_glfwPosY = settings.get<WindowPosY>().value;
    int &m_glfwSizeX = settings.get<WindowSizeX>().value;
    int &m_glfwSizeY = settings.get<WindowSizeY>().value;
    unsigned int m_VRAMTexture = 0;

    unsigned int m_offscreenFrameBuffer = 0;
    unsigned int m_offscreenTextures[2] = {0, 0};
    unsigned int m_offscreenDepthBuffer = 0;
    int m_currentTexture = -1;

    ImVec4 m_backgroundColor = ImColor(114, 144, 154);
    ImVec2 m_renderSize = ImVec2(1, 1);

    float m_renderRatio = 3.0f / 4.0f;
    bool &m_fullscreen = {settings.get<Fullscreen>().value};

    // GUI
    typedef Setting<bool, TYPESTRING("Fullscreen"), false> Fullscreen;
    typedef Setting<bool, TYPESTRING("FullscreenRender"), true> FullscreenRender;
    typedef Setting<bool, TYPESTRING("ShowMenu")> ShowMenu;
    typedef Setting<bool, TYPESTRING("ShowBiosCounters")> ShowBiosCounters;
    typedef Setting<bool, TYPESTRING("ShowLog")> ShowLog;
    typedef Setting<int, TYPESTRING("WindowPosX"), 0> WindowPosX;
    typedef Setting<int, TYPESTRING("WindowPosY"), 0> WindowPosY;
    typedef Setting<int, TYPESTRING("WindowSizeX"), 1280> WindowSizeX;
    typedef Setting<int, TYPESTRING("WindowSizeY"), 800> WindowSizeY;
    Settings<Fullscreen, FullscreenRender, ShowMenu, ShowBiosCounters, ShowLog, WindowPosX, WindowPosY, WindowSizeX,
             WindowSizeY>
        settings;
    bool &m_fullscreenRender = {settings.get<FullscreenRender>().value};
    bool &m_showMenu = {settings.get<ShowMenu>().value};
    bool m_showDemo = false;
    bool m_showAbout = false;
    bool m_showInterruptsScaler = false;
    Widgets::Log m_log = {settings.get<ShowLog>().value};
    struct MemoryEditorWrapper {
        MemoryEditorWrapper() {
            editor.OptShowDataPreview = true;
            editor.OptUpperCaseHex = false;
        }
        MemoryEditor editor;
        std::function<const char *()> title;
        bool &show = editor.Open;
        void MenuItem() { ImGui::MenuItem(title(), nullptr, &show); }
        void draw(void *mem, size_t size, uint32_t baseAddr = 0) { editor.DrawWindow(title(), mem, size, baseAddr); }
    };
    std::string m_stringHolder;
    MemoryEditorWrapper m_mainMemEditors[8];
    MemoryEditorWrapper m_parallelPortEditor;
    MemoryEditorWrapper m_scratchPadEditor;
    MemoryEditorWrapper m_hwrEditor;
    MemoryEditorWrapper m_biosEditor;
    Widgets::Registers m_registers;
    Widgets::Assembly m_assembly = {&m_mainMemEditors[0].editor, &m_hwrEditor.editor};
    Widgets::FileDialog m_openIsoFileDialog = {[]() { return _("Open Image"); }};
    Widgets::FileDialog m_selectBiosDialog = {[]() { return _("Select BIOS"); }};
    Widgets::FileDialog m_selectBiosOverlayDialog = {[]() { return _("Select BIOS Overlay"); }};
    int m_selectedBiosOverlayId;
    Widgets::Breakpoints m_breakpoints;
    std::vector<std::string> m_overlayFileOffsets;
    std::vector<std::string> m_overlayLoadOffsets;
    std::vector<std::string> m_overlayLoadSizes;

    bool m_showCfg = false;
    bool &m_showBiosCounters = {settings.get<ShowBiosCounters>().value};
    bool m_skipBiosUnknowns = true;

    const flags::args &m_args;
    bool m_scheduleSoftReset = false;
    bool m_scheduleHardReset = false;

    Widgets::VRAMViewer m_mainVRAMviewer;
    Widgets::VRAMViewer m_clutVRAMviewer;
    Widgets::VRAMViewer m_VRAMviewers[4];
};

}  // namespace PCSX
