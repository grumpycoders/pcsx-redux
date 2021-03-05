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

#include <GL/gl3w.h>
#include <stdarg.h>

#include <string>

#include "core/system.h"
#include "flags.h"
#include "fmt/printf.h"
#include "gui/widgets/assembly.h"
#include "gui/widgets/breakpoints.h"
#include "gui/widgets/console.h"
#include "gui/widgets/dwarf.h"
#include "gui/widgets/filedialog.h"
#include "gui/widgets/log.h"
#include "gui/widgets/luaeditor.h"
#include "gui/widgets/luainspector.h"
#include "gui/widgets/registers.h"
#include "gui/widgets/source.h"
#include "gui/widgets/types.h"
#include "gui/widgets/vram-viewer.h"
#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"
#include "support/eventbus.h"
#include "support/settings.h"

#if defined(__APPLE__)
#define GL_SHADER_VERSION "#version 410\n"
#else
#define GL_SHADER_VERSION "#version 300 es\n"
#endif

struct GLFWwindow;

namespace PCSX {

class GUI final {
  public:
    GUI(const flags::args &args) : m_args(args), m_listener(g_system->m_eventBus) {}
    void init();
    void close();
    void update(bool vsync = false);
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
    class Notifier {
      public:
        Notifier(std::function<const char *()> title) : m_title(title) {}
        void notify(const std::string &message) {
            m_message = message;
            ImGui::OpenPopup(m_title());
        }
        bool draw() {
            bool done = false;
            if (ImGui::BeginPopupModal(m_title(), NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::TextUnformatted(m_message.c_str());
                if (ImGui::Button(_("Ok"), ImVec2(120, 0))) {
                    ImGui::CloseCurrentPopup();
                    done = true;
                }
                ImGui::EndPopup();
            }
            return done;
        }

      private:
        const std::function<const char *()> m_title;
        std::string m_message;
    };
    void addNotification(const char *fmt, va_list args) {
        char notification[1024];
        vsnprintf(notification, 1023, fmt, args);
        notification[1023] = 0;
        m_notifier.notify(notification);
    }

    void magicOpen(const char *path);

    static void checkGL();

    static const char *glErrorToString(GLenum error) {
        static const std::map<GLenum, const char *> glErrorMap = {
            {GL_NO_ERROR, "GL_NO_ERROR"},
            {GL_INVALID_ENUM, "GL_INVALID_ENUM"},
            {GL_INVALID_VALUE, "GL_INVALID_VALUE"},
            {GL_INVALID_OPERATION, "GL_INVALID_OPERATION"},
            {GL_INVALID_FRAMEBUFFER_OPERATION, "GL_INVALID_FRAMEBUFFER_OPERATION"},
            {GL_OUT_OF_MEMORY, "GL_OUT_OF_MEMORY"},
            {GL_STACK_UNDERFLOW, "GL_STACK_UNDERFLOW"},
            {GL_STACK_OVERFLOW, "GL_STACK_OVERFLOW"},
        };
        auto f = glErrorMap.find(error);
        if (f == glErrorMap.end()) return "Unknown error";
        return f->second;
    }

  private:
    void saveCfg();

    void startFrame();
    void endFrame();

    bool configure();
    void showThemes();  // Theme window : Allows for custom imgui themes
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
    bool m_hasCoreProfile = false;
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
    typedef Setting<bool, TYPESTRING("ShowLog")> ShowLog;
    typedef Setting<bool, TYPESTRING("ShowLuaConsole")> ShowLuaConsole;
    typedef Setting<bool, TYPESTRING("ShowLuaInspector")> ShowLuaInspector;
    typedef Setting<bool, TYPESTRING("ShowLuaEditor")> ShowLuaEditor;
    typedef Setting<int, TYPESTRING("WindowPosX"), 0> WindowPosX;
    typedef Setting<int, TYPESTRING("WindowPosY"), 0> WindowPosY;
    typedef Setting<int, TYPESTRING("WindowSizeX"), 1280> WindowSizeX;
    typedef Setting<int, TYPESTRING("WindowSizeY"), 800> WindowSizeY;
    typedef Setting<int, TYPESTRING("IdleSwapInterval"), 1> IdleSwapInterval;
    typedef Setting<int, TYPESTRING("MainFontSize"), 16> MainFontSize;
    typedef Setting<int, TYPESTRING("MonoFontSize"), 16> MonoFontSize;
    Settings<Fullscreen, FullscreenRender, ShowMenu, ShowLog, WindowPosX, WindowPosY, WindowSizeX, WindowSizeY,
             IdleSwapInterval, ShowLuaConsole, ShowLuaInspector, ShowLuaEditor, MainFontSize, MonoFontSize>
        settings;
    bool &m_fullscreenRender = {settings.get<FullscreenRender>().value};
    bool &m_showMenu = {settings.get<ShowMenu>().value};
    int &m_idleSwapInterval = {settings.get<IdleSwapInterval>().value};
    bool m_showThemes = false;
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
    Widgets::FileDialog m_openBinaryDialog = {[]() { return _("Open Binary"); }};
    Widgets::FileDialog m_selectBiosDialog = {[]() { return _("Select BIOS"); }};
    Widgets::FileDialog m_selectBiosOverlayDialog = {[]() { return _("Select BIOS Overlay"); }};
    int m_selectedBiosOverlayId;
    Widgets::Breakpoints m_breakpoints;
    bool m_breakOnVSync = false;
    std::vector<std::string> m_overlayFileOffsets;
    std::vector<std::string> m_overlayLoadOffsets;
    std::vector<std::string> m_overlayLoadSizes;

    bool m_showCfg = false;
    bool m_showUiCfg = false;

    const flags::args &m_args;

    Widgets::VRAMViewer m_mainVRAMviewer;
    Widgets::VRAMViewer m_clutVRAMviewer;
    Widgets::VRAMViewer m_VRAMviewers[4];

    Widgets::Dwarf m_dwarf;

    Widgets::Types m_types;
    Widgets::Source m_source;
    Widgets::LuaEditor m_luaEditor = {settings.get<ShowLuaEditor>().value};

    EventBus::Listener m_listener;

    void shellReached();

    // ImGui themes: Defined in themes/imgui_themes.c
    const char *curr_item = "Default";
    void apply_theme(int n);
    void cherry_theme();
    void mono_theme();
    void dracula_theme();

    PCSX::u8string m_exeToLoad;
    Notifier m_notifier = {[]() { return _("Notification"); }};
    Widgets::Console m_luaConsole = {settings.get<ShowLuaConsole>().value};
    Widgets::LuaInspector m_luaInspector = {settings.get<ShowLuaInspector>().value};

    bool m_gotImguiUserError = false;
    std::string m_imguiUserError;

    ImFont *m_mainFont;
    ImFont *m_monoFont;

    ImFont *loadFont(const PCSX::u8string &name, int size, ImGuiIO &io, const ImWchar *ranges);

    bool m_reloadFonts = true;

  public:
    void useMainFont() { ImGui::PushFont(m_mainFont); }
    void useMonoFont() { ImGui::PushFont(m_monoFont); }
};

}  // namespace PCSX
