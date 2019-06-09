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

#include "core/system.h"
#include "gui/widgets/assembly.h"
#include "gui/widgets/breakpoints.h"
#include "gui/widgets/filedialog.h"
#include "gui/widgets/log.h"
#include "gui/widgets/registers.h"
#include "main/settings.h"

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
    void biosCounters();
    void about();

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
    bool &m_fullscreen = {settings.get<Fullscreen>().value};

    // GUI
    typedef Setting<bool, irqus::typestring<'F', 'u', 'l', 'l', 's', 'c', 'r', 'e', 'e', 'n'>, false> Fullscreen;
    typedef Setting<
        bool, irqus::typestring<'F', 'u', 'l', 'l', 's', 'c', 'r', 'e', 'e', 'n', 'R', 'e', 'n', 'd', 'e', 'r'>, true>
        FullscreenRender;
    typedef Setting<bool, irqus::typestring<'S', 'h', 'o', 'w', 'M', 'e', 'n', 'u'>> ShowMenu;
    typedef Setting<bool, irqus::typestring<'S', 'h', 'o', 'w', 'V', 'R', 'A', 'M'>> ShowVRAM;
    typedef Setting<bool,
                    irqus::typestring<'S', 'h', 'o', 'w', 'B', 'i', 'o', 's', 'C', 'o', 'u', 'n', 't', 'e', 'r', 's'>>
        ShowBiosCounters;
    typedef Setting<bool, irqus::typestring<'S', 'h', 'o', 'w', 'L', 'o', 'g'>> ShowLog;
    typedef Setting<int, irqus::typestring<'W', 'i', 'n', 'd', 'o', 'w', 'P', 'o', 's', 'X'>, SDL_WINDOWPOS_CENTERED>
        WindowPosX;
    typedef Setting<int, irqus::typestring<'W', 'i', 'n', 'd', 'o', 'w', 'P', 'o', 's', 'Y'>, SDL_WINDOWPOS_CENTERED>
        WindowPosY;
    typedef Setting<int, irqus::typestring<'W', 'i', 'n', 'd', 'o', 'w', 'S', 'i', 'z', 'e', 'X'>, 1280> WindowSizeX;
    typedef Setting<int, irqus::typestring<'W', 'i', 'n', 'd', 'o', 'w', 'S', 'i', 'z', 'e', 'Y'>, 800> WindowSizeY;
    Settings<Fullscreen, FullscreenRender, ShowMenu, ShowVRAM, ShowBiosCounters, ShowLog, WindowPosX, WindowPosY, WindowSizeX, WindowSizeY> settings;

    bool &m_fullscreenRender = {settings.get<FullscreenRender>().value};
    bool &m_showMenu = {settings.get<ShowMenu>().value};
    bool m_showDemo = false;
    bool &m_showVRAMwindow = {settings.get<ShowVRAM>().value};
    bool m_showAbout = false;
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
        void draw(void *mem, size_t size, uint32_t baseAddr = 0) {
            editor.DrawWindow(title(), mem, size, baseAddr);
        }
    };
    MemoryEditorWrapper m_mainMemEditors[8];
    std::string m_mainMemEditorsTitles[8];
    MemoryEditorWrapper m_parallelPortEditor;
    MemoryEditorWrapper m_scratchPadEditor;
    MemoryEditorWrapper m_hwrEditor;
    MemoryEditorWrapper m_biosEditor;
    Widgets::Registers m_registers;
    Widgets::Assembly m_assembly = {&m_mainMemEditors[0].editor, &m_hwrEditor.editor};
    Widgets::FileDialog m_openIsoFileDialog = {[]() { return _("Open Image"); }};
    Widgets::FileDialog m_selectBiosDialog = {[]() { return _("Select BIOS"); }};
    Widgets::Breakpoints m_breakpoints;

    bool m_showCfg = false;
    bool &m_showBiosCounters = {settings.get<ShowBiosCounters>().value};
    bool m_skipBiosUnknowns = true;

    const flags::args &m_args;
    bool m_scheduleSoftReset = false;
    bool m_scheduleHardReset = false;
};

}  // namespace PCSX
