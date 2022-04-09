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
#include "gui/widgets/callstacks.h"
#include "gui/widgets/console.h"
#include "gui/widgets/dwarf.h"
#include "gui/widgets/dynarec_disassembly.h"
#include "gui/widgets/events.h"
#include "gui/widgets/filedialog.h"
#include "gui/widgets/kernellog.h"
#include "gui/widgets/log.h"
#include "gui/widgets/luaeditor.h"
#include "gui/widgets/luainspector.h"
#include "gui/widgets/memcard_manager.h"
#include "gui/widgets/registers.h"
#include "gui/widgets/shader-editor.h"
#include "gui/widgets/sio1.h"
#include "gui/widgets/source.h"
#include "gui/widgets/types.h"
#include "gui/widgets/vram-viewer.h"
#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/eventbus.h"
#include "support/settings.h"
#include "widgets/memory_observer.h"

#if defined(__APPLE__)
#define GL_SHADER_VERSION "#version 410\n"
#else
#define GL_SHADER_VERSION "#version 300 es\n"
#endif

struct GLFWwindow;

namespace PCSX {

enum class LogClass : unsigned;

class GUI final {
    // imgui can't handle more than one "instance", so...
    static GUI *s_gui;
    void (*m_createWindowOldCallback)(ImGuiViewport *viewport) = nullptr;
    static void glfwKeyCallbackTrampoline(GLFWwindow *window, int key, int scancode, int action, int mods) {
        s_gui->glfwKeyCallback(window, key, scancode, action, mods);
    }
    void glfwKeyCallback(GLFWwindow *window, int key, int scancode, int action, int mods);
    void glErrorCallback(GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length, const GLchar *message);
    bool m_onlyLogGLErrors = false;
    std::vector<std::string> m_glErrors;

  public:
    void setOnlyLogGLErrors(bool value) { m_onlyLogGLErrors = value; }
    class ScopedOnlyLog {
      public:
        ScopedOnlyLog(GUI *gui) : m_gui(gui) { gui->setOnlyLogGLErrors(true); }
        ~ScopedOnlyLog() { m_gui->setOnlyLogGLErrors(false); }

      private:
        GUI *m_gui = nullptr;
    };
    std::vector<std::string> getGLerrors() { return std::move(m_glErrors); }
    GUI(const CommandLine::args &args) : m_args(args), m_listener(g_system->m_eventBus) {
        assert(s_gui == nullptr);
        s_gui = this;
    }
    ~GUI() {
        assert(s_gui == this);
        s_gui = nullptr;
    }
    void init();
    void setLua();
    void close();
    void update(bool vsync = false);
    void flip();
    void bindVRAMTexture();
    GLuint getVRAMTexture() { return m_VRAMTexture; }
    void setViewport();
    void setFullscreen(bool fullscreen);
    void setRawMouseMotion(bool value);
    bool addLog(LogClass logClass, const std::string &msg) {
        return m_log.addLog(magic_enum::enum_integer(logClass), msg);
    }
    void addLuaLog(const std::string &msg, bool error) {
        if (error) {
            m_luaConsole.addError(msg);
        } else {
            m_luaConsole.addLog(msg);
        }
    }
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
    void addNotification(const std::string &notification) { m_notifier.notify(notification); }

    void magicOpen(const char *path);

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
    bool showThemes();  // Theme window : Allows for custom imgui themes
    bool about();
    void interruptsScaler();

  public:
    static void normalizeDimensions(ImVec2 &vec, float ratio) {
        float r = vec.y / vec.x;
        if (r > ratio) {
            vec.y = vec.x * ratio;
        } else {
            vec.x = vec.y / ratio;
        }
        vec.x = roundf(vec.x);
        vec.y = roundf(vec.y);
        vec.x = std::max(vec.x, 1.0f);
        vec.y = std::max(vec.y, 1.0f);
    }

    const ImVec2 &getRenderSize() { return m_renderSize; }

  private:
    GLFWwindow *m_window = nullptr;
    bool m_hasCoreProfile = false;
    int &m_glfwPosX = settings.get<WindowPosX>().value;
    int &m_glfwPosY = settings.get<WindowPosY>().value;
    int &m_glfwSizeX = settings.get<WindowSizeX>().value;
    int &m_glfwSizeY = settings.get<WindowSizeY>().value;
    GLuint m_VRAMTexture = 0;

    unsigned int m_offscreenFrameBuffer = 0;
    unsigned int m_offscreenTextures[2] = {0, 0};
    unsigned int m_offscreenDepthBuffer = 0;
    int m_currentTexture = 0;

    ImVec4 m_backgroundColor = ImColor(114, 144, 154);
    ImVec2 m_framebufferSize = ImVec2(1, 1);  // Size of GLFW window framebuffer
    ImVec2 m_renderSize = ImVec2(1, 1);

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
    typedef Setting<int, TYPESTRING("GUITheme"), 0> GUITheme;
    typedef Setting<bool, TYPESTRING("RawMouseMotion"), false> EnableRawMouseMotion;
    Settings<Fullscreen, FullscreenRender, ShowMenu, ShowLog, WindowPosX, WindowPosY, WindowSizeX, WindowSizeY,
             IdleSwapInterval, ShowLuaConsole, ShowLuaInspector, ShowLuaEditor, MainFontSize, MonoFontSize, GUITheme,
             EnableRawMouseMotion>
        settings;
    bool &m_fullscreenRender = {settings.get<FullscreenRender>().value};
    bool &m_showMenu = {settings.get<ShowMenu>().value};
    int &m_idleSwapInterval = {settings.get<IdleSwapInterval>().value};
    bool m_showThemes = false;
    bool m_showDemo = false;
    bool m_showHandles = false;
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
    Widgets::MemoryObserver m_memoryObserver;
    Widgets::MemcardManager m_memcardManager;
    Widgets::Registers m_registers;
    Widgets::Assembly m_assembly;
    Widgets::Disassembly m_disassembly;
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

    const CommandLine::args &m_args;

    Widgets::VRAMViewer m_mainVRAMviewer;
    Widgets::VRAMViewer m_clutVRAMviewer;
    Widgets::VRAMViewer m_VRAMviewers[4];

    Widgets::Dwarf m_dwarf;

    Widgets::Types m_types;
    Widgets::Source m_source;
    Widgets::LuaEditor m_luaEditor = {settings.get<ShowLuaEditor>().value};

    Widgets::Events m_events;
    Widgets::KernelLog m_kernelLog;

    Widgets::CallStacks m_callstacks;

    Widgets::SIO1 m_sio1;

    EventBus::Listener m_listener;

    void shellReached();
    std::string buildSaveStateFilename(int i);
    void loadSaveState(const std::filesystem::path &filename);

    void applyTheme(int theme);
    void cherryTheme();
    void monoTheme();
    void draculaTheme();
    void oliveTheme();

    Notifier m_notifier = {[]() { return _("Notification"); }};
    Widgets::Console m_luaConsole = {settings.get<ShowLuaConsole>().value};
    Widgets::LuaInspector m_luaInspector = {settings.get<ShowLuaInspector>().value};

    bool m_gotImguiUserError = false;
    bool m_reportGLErrors = false;
    std::string m_imguiUserError;

    ImFont *m_mainFont;
    ImFont *m_monoFont;
    bool m_hasJapanese = false;

    ImFont *loadFont(const PCSX::u8string &name, int size, ImGuiIO &io, const ImWchar *ranges, bool combine = false);

    bool m_reloadFonts = true;
    Widgets::ShaderEditor m_outputShaderEditor = {"output"};

    static void byteRateToString(float rate, std::string &out);

  public:
    bool hasJapanese() { return m_hasJapanese; }
    bool m_setupScreenSize = true;
    bool m_clearTextures = true;
    Widgets::ShaderEditor m_offscreenShaderEditor = {"offscreen"};
    ImFont *getMono() { return m_monoFont ? m_monoFont : ImGui::GetIO().Fonts[0].Fonts[0]; }

    struct {
        bool empty() const { return filename.empty(); }
        void set(const PCSX::u8string &newfilename) {
            filename = newfilename;
            pauseAfterLoad = !g_system->running();
            if (!empty()) {
                g_system->start();
            }
        }
        PCSX::u8string &&get() { return std::move(filename); }
        bool hasToPause() { return pauseAfterLoad; }

      private:
        PCSX::u8string filename;
        bool pauseAfterLoad = true;
    } m_exeToLoad;

    bool &isRawMouseMotionEnabled() { return settings.get<EnableRawMouseMotion>().value; }
    void useMainFont() { ImGui::PushFont(m_mainFont); }
    void useMonoFont() { ImGui::PushFont(m_monoFont); }
};

}  // namespace PCSX
