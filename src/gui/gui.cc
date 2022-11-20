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

// These need to go first
#include "support/windowswrapper.h"
#ifdef _WIN32
#include <shellapi.h>
#endif

// And only then we can load the rest
#define GLFW_INCLUDE_NONE
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <assert.h>

#include <algorithm>
#include <ctime>
#include <exception>
#include <fstream>
#include <iomanip>
#include <type_traits>
#include <unordered_set>

#include "clip/clip.h"
#include "core/binloader.h"
#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/debug.h"
#include "core/gdb-server.h"
#include "core/gpu.h"
#include "core/pad.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sio1-server.h"
#include "core/sio1.h"
#include "core/sstate.h"
#include "core/web-server.h"
#include "flags.h"
#include "fmt/chrono.h"
#include "gpu/soft/externals.h"
#include "gui/gui.h"
#include "gui/resources.h"
#include "gui/shaders/crt-lottes.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"
#include "imgui_stdlib.h"
#include "json.hpp"
#include "lua/glffi.h"
#include "lua/luawrapper.h"
#include "magic_enum/include/magic_enum.hpp"
#include "spu/interface.h"
#include "support/uvfile.h"
#include "support/zfile.h"
#include "tracy/Tracy.hpp"

#ifdef _WIN32
extern "C" {
_declspec(dllexport) DWORD NvOptimusEnablement = 1;
_declspec(dllexport) DWORD AmdPowerXpressRequestHighPerformance = 1;
}

void PCSX::GUI::openUrl(const std::string_view& url) {
    std::string storage = std::string(url);
    ShellExecuteA(0, 0, storage.c_str(), 0, 0, SW_SHOW);
}
#elif defined(__APPLE__) && defined(__MACH__)
#include <stdlib.h>
void PCSX::GUI::openUrl(const std::string_view& url) {
    auto cmd = fmt::format("open {}", url);
    system(cmd.c_str());
}
#else
#include <stdlib.h>
void PCSX::GUI::openUrl(const std::string_view& url) {
    auto cmd = fmt::format("xdg-open {}", url);
    system(cmd.c_str());
}
#endif

using json = nlohmann::json;

static std::function<void(const char*)> s_imguiUserErrorFunctor = nullptr;
static void thrower(const char* msg) { throw std::runtime_error(msg); }
extern "C" void pcsxStaticImguiUserError(const char* msg) {
    if (s_imguiUserErrorFunctor) {
        s_imguiUserErrorFunctor(msg);
    } else {
        thrower(msg);
    }
}

extern "C" void pcsxStaticImguiAssert(int exp, const char* msg) {
    if (!exp) thrower(msg);
}

PCSX::GUI* PCSX::GUI::s_gui = nullptr;

void PCSX::GUI::setFullscreen(bool fullscreen) {
    m_fullscreen = fullscreen;
    if (fullscreen) {
        glfwGetWindowPos(m_window, &m_glfwPosX, &m_glfwPosY);
        glfwGetWindowSize(m_window, &m_glfwSizeX, &m_glfwSizeY);
        const GLFWvidmode* mode = glfwGetVideoMode(glfwGetPrimaryMonitor());
        glfwSetWindowMonitor(m_window, glfwGetPrimaryMonitor(), 0, 0, mode->width, mode->height, GLFW_DONT_CARE);
    } else {
        glfwSetWindowMonitor(m_window, nullptr, m_glfwPosX, m_glfwPosY, m_glfwSizeX, m_glfwSizeY, GLFW_DONT_CARE);
    }
}

void PCSX::GUI::setRawMouseMotion(bool value) {
    isRawMouseMotionEnabled() = value;
    if (value) {
        if (glfwRawMouseMotionSupported()) {
            glfwSetInputMode(m_window, GLFW_CURSOR, GLFW_CURSOR_DISABLED);
            glfwSetInputMode(m_window, GLFW_RAW_MOUSE_MOTION, GLFW_TRUE);
        }
    } else {
        glfwSetInputMode(m_window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);
    }
}

static PCSX::GUI* s_this = nullptr;

static void drop_callback(GLFWwindow* window, int count, const char** paths) {
    if (count != 1) return;
    s_this->magicOpen(paths[0]);
}

static void ShowHelpMarker(const char* desc) {
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void LoadImguiBindings(lua_State* lState);

ImFont* PCSX::GUI::loadFont(const PCSX::u8string& name, int size, ImGuiIO& io, const ImWchar* ranges, bool combine) {
    const System::Range knownRange = System::Range(reinterpret_cast<uintptr_t>(ranges));
    if (knownRange == System::Range::KOREAN) ranges = io.Fonts->GetGlyphRangesKorean();
    if (knownRange == System::Range::JAPANESE) ranges = io.Fonts->GetGlyphRangesJapanese();
    if (knownRange == System::Range::CHINESE_FULL) ranges = io.Fonts->GetGlyphRangesChineseFull();
    if (knownRange == System::Range::CHINESE_SIMPLIFIED) ranges = io.Fonts->GetGlyphRangesChineseSimplifiedCommon();
    if (knownRange == System::Range::CYRILLIC) ranges = io.Fonts->GetGlyphRangesCyrillic();
    if (knownRange == System::Range::THAI) ranges = io.Fonts->GetGlyphRangesThai();
    if (knownRange == System::Range::VIETNAMESE) ranges = io.Fonts->GetGlyphRangesVietnamese();

    decltype(s_imguiUserErrorFunctor) backup = [](const char*) {};
    std::swap(backup, s_imguiUserErrorFunctor);
    ImFontConfig cfg;
    cfg.MergeMode = combine;
    ImFont* ret = nullptr;
    std::filesystem::path path = name;
    g_system->findResource(
        [&ret, fonts = io.Fonts, size, &cfg, ranges](const std::filesystem::path& filename) mutable {
            ret = fonts->AddFontFromFileTTF(reinterpret_cast<const char*>(filename.u8string().c_str()), size, &cfg,
                                            ranges);
            return ret != nullptr;
        },
        path, "fonts", std::filesystem::path("third_party") / "noto");
    std::swap(backup, s_imguiUserErrorFunctor);
    return ret;
}

void PCSX::GUI::glErrorCallback(GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length,
                                const GLchar* message) {
    const auto severityFilter = g_emulator->settings.get<Emulator::SettingGLErrorReportingSeverity>().value;
    switch (severity) {
        case GL_DEBUG_SEVERITY_MEDIUM:
            if (severityFilter >= 3) return;
            break;
        case GL_DEBUG_SEVERITY_LOW:
            if (severityFilter >= 2) return;
            break;
        case GL_DEBUG_SEVERITY_NOTIFICATION:
            if (severityFilter >= 1) return;
            break;
    }
    static auto sourceToString = [](GLenum source) -> const char* {
        switch (source) {
            case GL_DEBUG_SOURCE_API:
                return "API";
            case GL_DEBUG_SOURCE_WINDOW_SYSTEM:
                return "Window System";
            case GL_DEBUG_SOURCE_SHADER_COMPILER:
                return "Shader Compiler";
            case GL_DEBUG_SOURCE_THIRD_PARTY:
                return "Third Party";
            case GL_DEBUG_SOURCE_APPLICATION:
                return "Application";
            case GL_DEBUG_SOURCE_OTHER:
                return "Other";
            default:
                return "Unknown";
        }
    };

    static auto typeToString = [](GLenum type) -> const char* {
        switch (type) {
            case GL_DEBUG_TYPE_ERROR:
                return "Error";
            case GL_DEBUG_TYPE_DEPRECATED_BEHAVIOR:
                return "Deprecated Behavior";
            case GL_DEBUG_TYPE_UNDEFINED_BEHAVIOR:
                return "Undefined Behavior";
            case GL_DEBUG_TYPE_PORTABILITY:
                return "Portability";
            case GL_DEBUG_TYPE_PERFORMANCE:
                return "Performance";
            case GL_DEBUG_TYPE_MARKER:
                return "Marker";
            case GL_DEBUG_TYPE_PUSH_GROUP:
                return "Push Group";
            case GL_DEBUG_TYPE_POP_GROUP:
                return "Pop Group";
            case GL_DEBUG_TYPE_OTHER:
                return "Other";
            default:
                return "Unknown";
        }
    };
    static auto severityToString = [](GLenum severity) -> const char* {
        switch (severity) {
            case GL_DEBUG_SEVERITY_HIGH:
                return "High";
            case GL_DEBUG_SEVERITY_MEDIUM:
                return "Medium";
            case GL_DEBUG_SEVERITY_LOW:
                return "Low";
            case GL_DEBUG_SEVERITY_NOTIFICATION:
                return "Notification";
            default:
                return "Unknown";
        }
    };
    std::string fullmessage =
        fmt::format("Got OpenGL callback from \"{}\", type \"{}\", severity {}: {}\n", sourceToString(source),
                    typeToString(type), severityToString(severity), message);
    if (m_onlyLogGLErrors) {
        m_glErrors.push_back(std::move(fullmessage));
    } else {
#ifdef _WIN32
        if (IsDebuggerPresent()) __debugbreak();
#endif
        g_system->log(LogClass::UI, std::move(fullmessage));
        if (type == GL_DEBUG_TYPE_ERROR) throw std::runtime_error("Got an OpenGL error");
    }
}

void PCSX::GUI::setLua(Lua L) {
    L.load(R"(
print("PCSX-Redux Lua Console")
print(jit.version)
print((function(status, ...)
  local ret = "JIT: " .. (status and "ON" or "OFF")
  for i, v in ipairs({...}) do
    ret = ret .. " " .. v
  end
  return ret
end)(jit.status()))
)",
           "gui startup");
    LoadImguiBindings(L.getState());
    LuaFFI::open_gl(L);
    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("settings");
    L.push("gui");
    settings.pushValue(L);
    L.settable();
    L.pop();
    L.pop();
    auto offscreenStatus = m_offscreenShaderEditor.compile(this);
    auto outputStatus = m_outputShaderEditor.compile(this);
    if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
        m_offscreenShaderEditor.setFallbacks();
        m_outputShaderEditor.setFallbacks();
        offscreenStatus = m_offscreenShaderEditor.compile(this);
        outputStatus = m_outputShaderEditor.compile(this);
    }
    if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
        g_system->log(LogClass::UI, "Failed to compile output shaders. You won't be able to see anything");
        g_system->log(LogClass::UI, "%s", offscreenStatus.getError());
        g_system->log(LogClass::UI, "%s", outputStatus.getError());
    }
}

void PCSX::GUI::init() {
    int result;

    s_imguiUserErrorFunctor = [this](const char* msg) {
        m_gotImguiUserError = true;
        m_imguiUserError = msg;
    };
    m_luaConsole.setCmdExec([this](const std::string& cmd) {
        ScopedOnlyLog scopedOnlyLog(this);
        try {
            g_emulator->m_lua->load(cmd, "console", false);
            g_emulator->m_lua->pcall();
            for (const auto& error : m_glErrors) {
                m_luaConsole.addError(error);
                if (m_args.get<bool>("lua_stdout", false)) {
                    fprintf(stderr, "%s\n", error.c_str());
                }
            }
            m_glErrors.clear();
        } catch (std::exception& e) {
            m_luaConsole.addError(e.what());
            if (m_args.get<bool>("lua_stdout", false)) {
                fprintf(stderr, "%s\n", e.what());
            }
        }
    });

    glfwSetErrorCallback([](int error, const char* description) {
        g_system->log(LogClass::UI, "Glfw Error %d: %s\n", error, description);
    });
    if (!glfwInit()) {
        throw std::runtime_error("Failed to initialize GLFW");
    }

    m_listener.listen<Events::Quitting>([this](const auto& event) { saveCfg(); });
    m_listener.listen<Events::ExecutionFlow::ShellReached>([this](const auto& event) { shellReached(); });
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {
        glfwSwapInterval(m_idleSwapInterval);
        glfwSetInputMode(m_window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);
    });
    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) {
        glfwSwapInterval(0);
        setRawMouseMotion(isRawMouseMotionEnabled());
    });

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    m_hasCoreProfile = true;

    m_window = glfwCreateWindow(1280, 800, "PCSX-Redux", nullptr, nullptr);

    if (!m_window) {
        g_system->log(LogClass::UI,
                      "GLFW failed to create window with OpenGL core profile 3.2, retrying with any 3.0 profile\n");
        glfwDefaultWindowHints();
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_ANY_PROFILE);
        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
        m_hasCoreProfile = false;

        m_window = glfwCreateWindow(1280, 800, "PCSX-Redux", nullptr, nullptr);
    }

    if (!m_window) {
        throw std::runtime_error("Unable to create main Window. Check OpenGL drivers.");
    }
    glfwMakeContextCurrent(m_window);
    glfwSwapInterval(0);

    s_this = this;
    glfwSetDropCallback(m_window, drop_callback);
    glfwSetWindowSizeCallback(m_window, [](GLFWwindow*, int, int) { s_this->m_setupScreenSize = true; });

    Resources::loadIcon([this](const uint8_t* data, uint32_t size) {
        clip::image img;
        if (!img.import_from_png(data, size)) return;
        int x = img.spec().width;
        int y = img.spec().height;
        GLFWimage image;
        image.width = x;
        image.height = y;
        image.pixels = reinterpret_cast<unsigned char*>(img.data());
        glfwSetWindowIcon(m_window, 1, &image);
    });

    result = gl3wInit();
    if (result) {
        throw std::runtime_error("Unable to initialize OpenGL layer. Check OpenGL drivers.");
    }

    // Setup ImGui binding
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    {
        io.IniFilename = nullptr;
        std::ifstream cfg("pcsx.json");
        auto& emuSettings = PCSX::g_emulator->settings;
        const bool resetUI = m_args.get<bool>("resetui", false);
        json j;
        bool safeMode = m_args.get<bool>("safe").value_or(false) || m_args.get<bool>("testmode").value_or(false);
        if (cfg.is_open() && !safeMode) {
            try {
                cfg >> j;
            } catch (...) {
            }
            if (!resetUI && (j.count("imgui") == 1) && j["imgui"].is_string()) {
                std::string imguicfg = j["imgui"];
                ImGui::LoadIniSettingsFromMemory(imguicfg.c_str(), imguicfg.size());
            }
            if ((j.count("emulator") == 1) && j["emulator"].is_object()) {
                emuSettings.deserialize(j["emulator"]);
            }
            if ((j.count("gui") == 1 && j["gui"].is_object())) {
                settings.deserialize(j["gui"]);
            }
            if ((j.count("loggers") == 1 && j["loggers"].is_object())) {
                m_log.deserialize(j["loggers"]);
            }

            auto& windowSizeX = settings.get<WindowSizeX>();
            auto& windowSizeY = settings.get<WindowSizeY>();
            if (!windowSizeX || resetUI) {
                windowSizeX.reset();
            }
            if (!windowSizeY || resetUI) {
                windowSizeY.reset();
            }
            if (resetUI) {
                settings.get<WindowPosX>().reset();
                settings.get<WindowPosY>().reset();
            }

            glfwSetWindowPos(m_window, settings.get<WindowPosX>(), settings.get<WindowPosY>());
            glfwSetWindowSize(m_window, windowSizeX, windowSizeY);
            PCSX::g_emulator->m_spu->setCfg(j);
            PCSX::g_emulator->m_pads->setCfg(j);
        } else {
            PCSX::g_emulator->m_pads->setDefaults();
            saveCfg();
        }

        g_system->m_eventBus->signal(Events::SettingsLoaded{safeMode});
        if (emuSettings.get<PCSX::Emulator::SettingAutoUpdate>() && !g_system->getVersion().failed()) {
            m_update.downloadUpdateInfo(
                g_system->getVersion(),
                [this](bool success) {
                    if (success) {
                        m_updateAvailable = true;
                    }
                },
                g_system->getLoop());
        }

        setFullscreen(m_fullscreen);
        const auto currentTheme = emuSettings.get<Emulator::SettingGUITheme>().value;  // On boot: reload GUI theme
        applyTheme(currentTheme);
    }
    if (!g_system->running()) glfwSwapInterval(m_idleSwapInterval);

    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    // io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports;
    io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;

    ImGui_ImplGlfw_InitForOpenGL(m_window, true);
    ImGuiPlatformIO& platform_io = ImGui::GetPlatformIO();
    io.SetClipboardTextFn = [](void*, const char* text) -> void { clip::set_text(text); };
    io.GetClipboardTextFn = [](void*) -> const char* {
        static std::string clipboard;
        clip::get_text(clipboard);
        return clipboard.c_str();
    };
    m_createWindowOldCallback = platform_io.Platform_CreateWindow;
    platform_io.Platform_CreateWindow = [](ImGuiViewport* viewport) {
        s_gui->m_createWindowOldCallback(viewport);
        // absolutely horrendous hack, but the only way we have to grab the
        // newly created GLFWwindow pointer...
        auto window = *reinterpret_cast<GLFWwindow**>(viewport->PlatformUserData);
        glfwSetKeyCallback(window, glfwKeyCallbackTrampoline);
    };
    glfwSetKeyCallback(m_window, glfwKeyCallbackTrampoline);
    // Some bad GPU drivers (*cough* Intel) don't like mixed shaders versions,
    // and will silently fail to execute them.
    // This is just a bad heuristic to try and keep it the same version.
    ImGui_ImplOpenGL3_Init(m_hasCoreProfile ? GL_SHADER_VERSION : nullptr);

    if (glDebugMessageCallback &&
        (g_emulator->settings.get<Emulator::SettingGLErrorReporting>() || m_args.get<bool>("testmode", false))) {
        m_reportGLErrors = true;
        glEnable(GL_DEBUG_OUTPUT_SYNCHRONOUS);
        glEnable(GL_DEBUG_OUTPUT);
        GLDEBUGPROC callback = [](GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length,
                                  const GLchar* message, const void* userParam) {
            GUI* self = reinterpret_cast<GUI*>(const_cast<void*>(userParam));
            self->glErrorCallback(source, type, id, severity, length, message);
        };
        glDebugMessageCallback(callback, this);
    } else {
        g_system->log(LogClass::UI,
                      _("Warning: OpenGL error reporting disabled. See About dialog for more information.\n"));
    }

    glDisable(GL_CULL_FACE);
    // offscreen stuff
    glGenFramebuffers(1, &m_offscreenFrameBuffer);
    glGenTextures(2, m_offscreenTextures);
    glGenRenderbuffers(1, &m_offscreenDepthBuffer);

    m_mainVRAMviewer.setMain();
    m_mainVRAMviewer.setTitle([]() { return _("Main VRAM Viewer"); });
    m_clutVRAMviewer.setTitle([]() { return _("CLUT VRAM selector"); });
    m_memcardManager.initTextures();

    unsigned counter = 1;
    for (auto& viewer : m_VRAMviewers) {
        viewer.setTitle([counter]() { return _("Vram Viewer #") + std::to_string(counter); });
        counter++;
    }

    m_clutVRAMviewer.setClutDestination(&m_mainVRAMviewer);

    counter = 1;
    for (auto& editor : m_mainMemEditors) {
        editor.title = [counter, this]() {
            m_stringHolder = (_("Memory Editor #") + std::to_string(counter));
            return m_stringHolder.c_str();
        };
        counter++;
        editor.show = false;
    }
    m_parallelPortEditor.title = []() { return _("Parallel Port"); };
    m_parallelPortEditor.show = false;
    m_scratchPadEditor.title = []() { return _("Scratch Pad"); };
    m_scratchPadEditor.show = false;
    m_hwrEditor.title = []() { return _("Hardware Registers"); };
    m_hwrEditor.show = false;
    m_biosEditor.title = []() { return _("BIOS"); };
    m_biosEditor.show = false;
    m_vramEditor.title = []() { return _("VRAM"); };
    m_vramEditor.editor.WriteFn = [](uint8_t* data, size_t offset, uint8_t writtenByte) {
        constexpr size_t vramWidth = 1024;
        constexpr size_t stride = vramWidth * sizeof(uint16_t);  // Number of bytes per line of VRAM

        // x and y coordinates of pixel
        const auto x = (offset % stride) / sizeof(uint16_t);
        const auto y = offset / stride;
        const bool offsetIsOdd = (offset & 1) == 1;
        const auto maskedOffset = offset & ~1;
        uint16_t newPixel;

        if (offsetIsOdd) {
            newPixel = (writtenByte << 8) | data[maskedOffset];
        } else {
            newPixel = writtenByte | (data[maskedOffset] << 8);
        }

        g_emulator->m_gpu->partialUpdateVRAM(x, y, 1, 1, &newPixel);
    };
    m_vramEditor.show = false;

    m_offscreenShaderEditor.init();
    m_outputShaderEditor.init();

    m_listener.listen<Events::GUI::JumpToMemory>([this](auto& event) {
        const uint32_t base = (event.address >> 20) & 0xffc;
        const uint32_t real = event.address & 0x7fffff;
        const uint32_t size = event.size;
        auto changeDataType = [](MemoryEditor* editor, int size) {
            bool isSigned = false;
            switch (editor->PreviewDataType) {
                case ImGuiDataType_S8:
                case ImGuiDataType_S16:
                case ImGuiDataType_S32:
                case ImGuiDataType_S64:
                    isSigned = true;
                    break;
            }
            switch (size) {
                case 1:
                    editor->PreviewDataType = isSigned ? ImGuiDataType_S8 : ImGuiDataType_U8;
                    break;
                case 2:
                    editor->PreviewDataType = isSigned ? ImGuiDataType_S16 : ImGuiDataType_U16;
                    break;
                case 4:
                    editor->PreviewDataType = isSigned ? ImGuiDataType_S32 : ImGuiDataType_U32;
                    break;
            }
        };
        if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
            if (real < 0x00800000) {
                m_mainMemEditors[0].editor.GotoAddrAndHighlight(real, real + size);
                changeDataType(&m_mainMemEditors[0].editor, size);
            }
        } else if (base == 0x1f8) {
            if (real >= 0x1000 && real < 0x3000) {
                m_hwrEditor.editor.GotoAddrAndHighlight(real - 0x1000, real - 0x1000 + size);
                changeDataType(&m_hwrEditor.editor, size);
            }
        }
    });

    startFrame();
    m_currentTexture ^= 1;
    flip();
}

void PCSX::GUI::close() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(m_window);
    glfwTerminate();
}

void PCSX::GUI::saveCfg() {
    std::ofstream cfg("pcsx.json");
    json j;

    glfwGetWindowPos(m_window, &m_glfwPosX, &m_glfwPosY);
    glfwGetWindowSize(m_window, &m_glfwSizeX, &m_glfwSizeY);

    j["imgui"] = ImGui::SaveIniSettingsToMemory(nullptr);
    j["SPU"] = PCSX::g_emulator->m_spu->getCfg();
    j["emulator"] = PCSX::g_emulator->settings.serialize();
    j["gui"] = settings.serialize();
    j["loggers"] = m_log.serialize();
    j["pads"] = PCSX::g_emulator->m_pads->getCfg();
    cfg << std::setw(2) << j << std::endl;
}

void PCSX::GUI::glfwKeyCallback(GLFWwindow* window, int key, int scancode, int action, int mods) {
    ImGui_ImplGlfw_KeyCallback(window, key, scancode, action, mods);
    g_system->m_eventBus->signal(Events::Keyboard{key, scancode, action, mods});
}

void PCSX::GUI::startFrame() {
    ZoneScoped;
    uv_run(g_system->getLoop(), UV_RUN_NOWAIT);
    auto L = *g_emulator->m_lua;
    L.getfield("AfterPollingCleanup", LUA_GLOBALSINDEX);
    if (!L.isnil()) {
        try {
            L.pcall();
        } catch (...) {
        }
        L.push();
        L.setfield("AfterPollingCleanup", LUA_GLOBALSINDEX);
    } else {
        L.pop();
    }
    if (glfwWindowShouldClose(m_window)) g_system->quit();
    glfwPollEvents();

    if (m_setupScreenSize) {
        const float renderRatio = settings.get<WidescreenRatio>() ? 9.0f / 16.0f : 3.0f / 4.0f;
        int w, h;

        glfwGetFramebufferSize(m_window, &w, &h);
        // Make width/height be 1 at minimum
        w = std::max<int>(w, 1);
        h = std::max<int>(h, 1);
        m_framebufferSize = ImVec2(w, h);
        m_renderSize = ImVec2(w, h);
        normalizeDimensions(m_renderSize, renderRatio);

        // Reset texture and framebuffer storage
        glBindTexture(GL_TEXTURE_2D, m_offscreenTextures[0]);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_renderSize.x, m_renderSize.y, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
        glBindTexture(GL_TEXTURE_2D, m_offscreenTextures[1]);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_renderSize.x, m_renderSize.y, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);

        if (m_clearTextures) {
            const auto allocSize = static_cast<size_t>(std::ceil(m_renderSize.x * m_renderSize.y * sizeof(uint32_t)));
            GLubyte* data = new GLubyte[allocSize]();
            for (int i = 0; i < 2; i++) {
                glBindTexture(GL_TEXTURE_2D, m_offscreenTextures[i]);
                glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, m_renderSize.x, m_renderSize.y, GL_RGBA, GL_UNSIGNED_BYTE,
                                data);
            }
            m_clearTextures = false;
            delete[] data;
        }

        glBindRenderbuffer(GL_RENDERBUFFER, m_offscreenDepthBuffer);
        glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH_COMPONENT24, m_renderSize.x, m_renderSize.y);
        m_setupScreenSize = false;
    }

    auto& io = ImGui::GetIO();

    if (m_reloadFonts) {
        m_reloadFonts = false;

        ImGui_ImplOpenGL3_DestroyFontsTexture();

        io.Fonts->Clear();
        io.Fonts->AddFontDefault();
        m_mainFont = loadFont(MAKEU8("NotoSans-Regular.ttf"), settings.get<MainFontSize>().value, io,
                              g_system->getLocaleRanges());
        for (auto e : g_system->getLocaleExtra()) {
            loadFont(e.first, settings.get<MainFontSize>().value, io, e.second, true);
        }
        // try loading the japanese font for memory card manager
        m_hasJapanese = loadFont(MAKEU8("NotoSansCJKjp-Regular.otf"), settings.get<MainFontSize>().value, io,
                                 reinterpret_cast<const ImWchar*>(PCSX::System::Range::JAPANESE), true);
        m_monoFont = loadFont(MAKEU8("NotoMono-Regular.ttf"), settings.get<MonoFontSize>().value, io, nullptr);
        io.Fonts->Build();
        io.FontDefault = m_mainFont;

        ImGui_ImplOpenGL3_CreateFontsTexture();
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    if (io.WantSaveIniSettings) {
        io.WantSaveIniSettings = false;
        saveCfg();
    }
    glBindFramebuffer(GL_FRAMEBUFFER, m_offscreenFrameBuffer);
    GLenum DrawBuffers[1] = {GL_COLOR_ATTACHMENT0};

    // this call seems to sometime fails when the window is minimized...?
    glDrawBuffers(1, DrawBuffers);  // "1" is the size of DrawBuffers

    // If kiosk mode is enabled, ignore hotkeys
    if (g_emulator->settings.get<Emulator::SettingKioskMode>().value) return;

    // Check hotkeys (TODO: Make configurable)
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        m_showMenu = !m_showMenu;
    }
    if (io.KeyAlt) {
        if (ImGui::IsKeyPressed(ImGuiKey_Enter)) setFullscreen(!m_fullscreen);
        if (io.KeyCtrl) {
            setRawMouseMotion(!isRawMouseMotionEnabled());
        }
    }

    if (ImGui::IsKeyPressed(ImGuiKey_F1)) {  // Save to quick-save slot
        saveSaveState(buildSaveStateFilename(0));
    }

    if (ImGui::IsKeyPressed(ImGuiKey_F2)) {  // Load from quick-save slot
        const auto saveStateName = buildSaveStateFilename(0);
        loadSaveState(saveStateName);
    }

    if (!g_system->running()) {
        if (ImGui::IsKeyPressed(ImGuiKey_F10)) {
            g_emulator->m_debug->stepOver();
        } else if (ImGui::IsKeyPressed(ImGuiKey_F11)) {
            if (ImGui::GetIO().KeyShift) {
                g_emulator->m_debug->stepOut();
            } else {
                g_emulator->m_debug->stepIn();
            }
        } else if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
            g_system->resume();
        }
    } else {
        if (ImGui::IsKeyPressed(ImGuiKey_Pause) || ImGui::IsKeyPressed(ImGuiKey_F6)) g_system->pause();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F8)) {
        if (ImGui::GetIO().KeyShift) {
            g_system->hardReset();
        } else {
            g_system->softReset();
        }
    }
}

void PCSX::GUI::setViewport() { glViewport(0, 0, m_renderSize.x, m_renderSize.y); }

void PCSX::GUI::flip() {
    glBindFramebuffer(GL_FRAMEBUFFER, m_offscreenFrameBuffer);
    glBindTexture(GL_TEXTURE_2D, m_offscreenTextures[m_currentTexture]);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);

    glBindRenderbuffer(GL_RENDERBUFFER, m_offscreenDepthBuffer);
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER, m_offscreenDepthBuffer);
    GLuint texture = m_offscreenTextures[m_currentTexture];
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    GLenum DrawBuffers[1] = {GL_COLOR_ATTACHMENT0};

    // this call seems to sometime fails when the window is minimized...?
    glDrawBuffers(1, DrawBuffers);  // "1" is the size of DrawBuffers
    assert(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);
    glClearColor(0, 0, 0, 0);
    glClearDepthf(0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glDisable(GL_CULL_FACE);
    m_currentTexture ^= 1;
}

void PCSX::GUI::endFrame() {
    constexpr float renderRatio = 3.0f / 4.0f;
    const int w = m_framebufferSize.x;
    const int h = m_framebufferSize.y;

    auto& io = ImGui::GetIO();
    // bind back the output frame buffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    auto& emuSettings = PCSX::g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();

    bool changed = false;

    m_offscreenShaderEditor.configure(this);
    m_outputShaderEditor.configure(this);

    if (m_fullscreenRender) {
        ImTextureID texture = reinterpret_cast<ImTextureID*>(m_offscreenTextures[m_currentTexture]);
        const auto basePos = ImGui::GetMainViewport()->Pos;
        const auto displayFramebufferScale = ImGui::GetIO().DisplayFramebufferScale;
        const auto logicalRenderSize =
            ImVec2(m_renderSize[0] / displayFramebufferScale[0], m_renderSize[1] / displayFramebufferScale[1]);
        ImGui::SetNextWindowPos(ImVec2((w - m_renderSize.x) / 2.0f / displayFramebufferScale[0] + basePos.x,
                                       (h - m_renderSize.y) / 2.0f / displayFramebufferScale[0] + basePos.y));
        ImGui::SetNextWindowSize(logicalRenderSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::Begin("FullScreenRender", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                         ImGuiWindowFlags_NoBringToFrontOnFocus);
        m_outputShaderEditor.renderWithImgui(this, texture, m_renderSize, logicalRenderSize);
        ImGui::End();
        ImGui::PopStyleVar(2);
    } else {
        ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(640, 480), ImGuiCond_FirstUseEver);
        bool outputShown = true;
        if (ImGui::Begin(
                _("Output"), &outputShown,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse)) {
            ImVec2 textureSize = ImGui::GetContentRegionAvail();
            normalizeDimensions(textureSize, renderRatio);
            ImTextureID texture = reinterpret_cast<ImTextureID*>(m_offscreenTextures[m_currentTexture]);
            m_outputShaderEditor.renderWithImgui(this, texture, m_renderSize, textureSize);
        }
        ImGui::End();
        if (!outputShown) m_fullscreenRender = true;
    }

    bool showOpenIsoFileDialog = false;
    bool showOpenBinaryDialog = false;

    if (m_showMenu || !m_fullscreenRender || !PCSX::g_system->running()) {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu(_("File"))) {
                showOpenIsoFileDialog = ImGui::MenuItem(_("Open Disk Image"));
                if (ImGui::MenuItem(_("Close Disk Image"))) {
                    PCSX::g_emulator->m_cdrom->setIso(new CDRIso());
                    PCSX::g_emulator->m_cdrom->check();
                }
                if (ImGui::MenuItem(_("Load binary"))) {
                    showOpenBinaryDialog = true;
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Dump save state proto schema"))) {
                    std::ofstream schema("sstate.proto");
                    SaveStates::ProtoFile::dumpSchema(schema);
                }

                if (ImGui::BeginMenu(_("Save state slots"))) {
                    if (ImGui::MenuItem(_("Quick-save slot"), "F1")) {
                        saveSaveState(buildSaveStateFilename(0));
                    }

                    for (auto i = 1; i < 10; i++) {
                        const auto str = fmt::format(f_("Slot {}"), i);
                        if (ImGui::MenuItem(str.c_str())) {
                            saveSaveState(buildSaveStateFilename(i));
                        }
                    }

                    ImGui::EndMenu();
                }

                if (ImGui::BeginMenu(_("Load state slots"))) {
                    if (ImGui::MenuItem(_("Quick-save slot"), "F2")) loadSaveState(buildSaveStateFilename(0));

                    for (auto i = 1; i < 10; i++) {
                        const auto str = fmt::format(f_("Slot {}"), i);
                        if (ImGui::MenuItem(str.c_str())) loadSaveState(buildSaveStateFilename(i));
                    }

                    ImGui::EndMenu();
                }

                static constexpr char globalSaveState[] = "global.sstate";

                if (ImGui::MenuItem(_("Save global state"))) {
                    saveSaveState(globalSaveState);
                }

                if (ImGui::MenuItem(_("Load global state"))) loadSaveState(globalSaveState);

                ImGui::Separator();
                if (ImGui::MenuItem(_("Open LID"))) {
                    PCSX::g_emulator->m_cdrom->setLidOpenTime(-1);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Close LID"))) {
                    PCSX::g_emulator->m_cdrom->setLidOpenTime(0);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Open and close LID"))) {
                    PCSX::g_emulator->m_cdrom->setLidOpenTime((int64_t)time(nullptr) + 2);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Reboot"))) {
                    g_system->quit(0x12eb007);
                }
                if (ImGui::MenuItem(_("Quit"))) {
                    g_system->quit();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Emulation"))) {
                if (ImGui::MenuItem(_("Start emulation"), "F5", nullptr, !g_system->running())) {
                    g_system->resume();
                }
                if (ImGui::MenuItem(_("Pause emulation"), "F6", nullptr, g_system->running())) {
                    g_system->pause();
                }
                if (ImGui::MenuItem(_("Soft Reset"), "F8")) {
                    g_system->softReset();
                }
                if (ImGui::MenuItem(_("Hard Reset"), "Shift+F8")) {
                    g_system->hardReset();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Configuration"))) {
                ImGui::MenuItem(_("Emulation"), nullptr, &m_showCfg);
                if (ImGui::MenuItem(_("Manage Memory Cards"), nullptr, &m_memcardManager.m_show)) {
                    m_memcardManager.m_frameCount = 0;  // Reset frame count when memcard manager is toggled
                }
                ImGui::MenuItem(_("GPU"), nullptr, &PCSX::g_emulator->m_gpu->m_showCfg);
                ImGui::MenuItem(_("SPU"), nullptr, &PCSX::g_emulator->m_spu->m_showCfg);
                ImGui::MenuItem(_("UI"), nullptr, &m_showUiCfg);
                ImGui::MenuItem(_("System"), nullptr, &m_showSysCfg);
                ImGui::MenuItem(_("Controls"), nullptr, &g_emulator->m_pads->m_showCfg);
                if (ImGui::BeginMenu(_("Shader presets"))) {
                    if (ImGui::MenuItem(_("Default shader"))) {
                        m_offscreenShaderEditor.setDefaults();
                        auto offscreenStatus = m_offscreenShaderEditor.compile(this);
                        m_outputShaderEditor.setDefaults();
                        auto outputStatus = m_outputShaderEditor.compile(this);

                        if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
                            m_offscreenShaderEditor.setFallbacks();
                            m_outputShaderEditor.setFallbacks();
                            offscreenStatus = m_offscreenShaderEditor.compile(this);
                            outputStatus = m_outputShaderEditor.compile(this);
                        }
                        if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
                            g_system->log(LogClass::UI,
                                          "Failed to compile output shaders. You won't be able to see anything");
                            g_system->log(LogClass::UI, "%s", offscreenStatus.getError());
                            g_system->log(LogClass::UI, "%s", outputStatus.getError());
                        }

                        m_offscreenShaderEditor.reset(this);
                        m_outputShaderEditor.reset(this);
                    }
                    if (ImGui::MenuItem(_("CRT-lottes shader"))) {
                        m_offscreenShaderEditor.setText(Shaders::CrtLottes::Offscreen::vert().data(),
                                                        Shaders::CrtLottes::Offscreen::frag().data(),
                                                        Shaders::CrtLottes::Offscreen::lua().data());
                        auto offscreenStatus = m_offscreenShaderEditor.compile(this);
                        m_outputShaderEditor.setText(Shaders::CrtLottes::Output::vert().data(),
                                                     Shaders::CrtLottes::Output::frag().data(),
                                                     Shaders::CrtLottes::Output::lua().data());
                        auto outputStatus = m_outputShaderEditor.compile(this);

                        if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
                            m_offscreenShaderEditor.setFallbacks();
                            m_outputShaderEditor.setFallbacks();
                            offscreenStatus = m_offscreenShaderEditor.compile(this);
                            outputStatus = m_outputShaderEditor.compile(this);
                        }
                        if (!offscreenStatus.isOk() || !outputStatus.isOk()) {
                            g_system->log(LogClass::UI,
                                          "Failed to compile output shaders. You won't be able to see anything");
                            g_system->log(LogClass::UI, "%s", offscreenStatus.getError());
                            g_system->log(LogClass::UI, "%s", outputStatus.getError());
                        }
                        m_offscreenShaderEditor.reset(this);
                        m_outputShaderEditor.reset(this);
                    }
                    ImGui::EndMenu();
                }
                if (ImGui::MenuItem(_("Configure Shaders"))) {
                    m_offscreenShaderEditor.setConfigure();
                    m_outputShaderEditor.setConfigure();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Debug"))) {
                ImGui::MenuItem(_("Show Logs"), nullptr, &m_log.m_show);
                ImGui::MenuItem(_("Show Lua Console"), nullptr, &m_luaConsole.m_show);
                ImGui::MenuItem(_("Show Lua Inspector"), nullptr, &m_luaInspector.m_show);
                ImGui::MenuItem(_("Show Lua editor"), nullptr, &m_luaEditor.m_show);
                if (ImGui::BeginMenu(_("VRAM viewers"))) {
                    ImGui::MenuItem(_("Show main VRAM viewer"), nullptr, &m_mainVRAMviewer.m_show);
                    ImGui::MenuItem(_("Show CLUT VRAM viewer"), nullptr, &m_clutVRAMviewer.m_show);
                    unsigned counter = 1;
                    for (auto& viewer : m_VRAMviewers) {
                        std::string title = _("Show VRAM viewer #") + std::to_string(counter);
                        ImGui::MenuItem(title.c_str(), nullptr, &viewer.m_show);
                        counter++;
                    }
                    ImGui::EndMenu();
                }
                ImGui::MenuItem(_("Show Registers"), nullptr, &m_registers.m_show);
                ImGui::MenuItem(_("Show Assembly"), nullptr, &m_assembly.m_show);
                if (PCSX::g_emulator->m_cpu->isDynarec()) {
                    ImGui::MenuItem(_("Show DynaRec Disassembly"), nullptr, &m_disassembly.m_show);
                } else {
                    ImGui::MenuItem(_("Show DynaRec Disassembly"), nullptr, false, false);
                    ShowHelpMarker(_(
                        R"(DynaRec Disassembler is not available in Interpreted CPU mode. Try enabling [Dynarec CPU]
in Configuration->Emulation, restart PCSX-Redux, then try again.)"));
                }
                ImGui::MenuItem(_("Show Breakpoints"), nullptr, &m_breakpoints.m_show);
                ImGui::MenuItem(_("Show Callstacks"), nullptr, &m_callstacks.m_show);
                ImGui::MenuItem(_("Breakpoint on vsync"), nullptr, &m_breakOnVSync);
                if (ImGui::BeginMenu(_("Memory Editors"))) {
                    for (auto& editor : m_mainMemEditors) {
                        editor.MenuItem();
                    }
                    m_parallelPortEditor.MenuItem();
                    m_scratchPadEditor.MenuItem();
                    m_hwrEditor.MenuItem();
                    m_biosEditor.MenuItem();
                    m_vramEditor.MenuItem();
                    ImGui::EndMenu();
                }
                ImGui::MenuItem(_("Show Memory Observer"), nullptr, &m_memoryObserver.m_show);
                ImGui::MenuItem(_("Show Typed Debugger"), nullptr, &m_typedDebugger.m_show);
                ImGui::MenuItem(_("Show Interrupts Scaler"), nullptr, &m_showInterruptsScaler);
                ImGui::MenuItem(_("Kernel Events"), nullptr, &m_events.m_show);
                ImGui::MenuItem(_("Kernel Handlers"), nullptr, &m_handlers.m_show);
                ImGui::MenuItem(_("Kernel Calls"), nullptr, &m_kernelLog.m_show);
                if (ImGui::BeginMenu(_("First Chance Exceptions"))) {
                    ImGui::PushItemFlag(ImGuiItemFlags_SelectableDontClosePopup, true);
                    constexpr auto& exceptions = magic_enum::enum_entries<PCSX::R3000Acpu::Exception>();
                    unsigned& s = debugSettings.get<Emulator::DebugSettings::FirstChanceException>().value;
                    for (auto& e : exceptions) {
                        unsigned f = 1 << static_cast<std::underlying_type<PCSX::R3000Acpu::Exception>::type>(e.first);
                        bool selected = s & f;
                        changed |= ImGui::MenuItem(std::string(e.second).c_str(), nullptr, &selected);
                        if (selected) {
                            s |= f;
                        } else {
                            s &= ~f;
                        }
                    }
                    ImGui::PopItemFlag();
                    ImGui::EndMenu();
                }
                ImGui::Separator();
                ImGui::MenuItem(_("Show SPU debug"), nullptr, &PCSX::g_emulator->m_spu->m_showDebug);
                ImGui::Separator();
                ImGui::MenuItem(_("Show GPU debug"), nullptr, &PCSX::g_emulator->m_gpu->m_showDebug);
                ImGui::Separator();
                ImGui::MenuItem(_("Show SIO1 debug"), nullptr, &m_sio1.m_show);
                ImGui::Separator();
                if (ImGui::MenuItem(_("Start GPU dump"))) {
                    PCSX::g_emulator->m_gpu->startDump();
                }
                if (ImGui::MenuItem(_("Stop GPU dump"))) {
                    PCSX::g_emulator->m_gpu->stopDump();
                }
                ImGui::Separator();
                ImGui::MenuItem(_("Fullscreen render"), nullptr, &m_fullscreenRender);
                ImGui::MenuItem(_("Show Output Shader Editor"), nullptr, &m_outputShaderEditor.m_show);
                ImGui::MenuItem(_("Show Offscreen Shader Editor"), nullptr, &m_offscreenShaderEditor.m_show);
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Help"))) {
                ImGui::MenuItem(_("Show ImGui Demo"), nullptr, &m_showDemo);
                ImGui::Separator();
                ImGui::MenuItem(_("Show UvFile information"), nullptr, &m_showHandles);
                ImGui::Separator();
                ImGui::MenuItem(_("About"), nullptr, &m_showAbout);
                ImGui::EndMenu();
            }
            ImGui::Separator();
            ImGui::Separator();
            ImGui::Text(_("CPU: %s"), g_emulator->m_cpu->getName().c_str());
            ImGui::Separator();
            ImGui::Text(_("GAME ID: %s"), g_emulator->m_cdrom->getCDRomID().c_str());
            ImGui::Separator();
            if (g_system->running()) {
                ImGui::Text(_("%.2f FPS (%.2f ms)"), ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);
                ImGui::Separator();
                uint32_t frameCount = g_emulator->m_spu->getFrameCount();
                ImGui::Text(_("%.2f ms audio buffer (%i frames)"), 1000.0f * frameCount / 44100.0f, frameCount);
            } else {
                ImGui::Text(_("Idle"));
            }

            ImGui::EndMainMenuBar();
        }
    }

    auto& isoPath = g_emulator->settings.get<Emulator::SettingIsoPath>();

    if (showOpenIsoFileDialog) {
        if (!isoPath.empty()) {
            m_openIsoFileDialog.m_currentPath = isoPath.value;
        }
        m_openIsoFileDialog.openDialog();
    }
    if (m_openIsoFileDialog.draw()) {
        isoPath.value = m_openIsoFileDialog.m_currentPath;
        changed = true;
        std::vector<PCSX::u8string> fileToOpen = m_openIsoFileDialog.selected();
        if (!fileToOpen.empty()) {
            PCSX::g_emulator->m_cdrom->setIso(new CDRIso(reinterpret_cast<const char*>(fileToOpen[0].c_str())));
            PCSX::g_emulator->m_cdrom->check();
        }
    }

    if (showOpenBinaryDialog) {
        if (!isoPath.empty()) {
            m_openBinaryDialog.m_currentPath = isoPath.value;
        }
        m_openBinaryDialog.openDialog();
    }
    if (m_openBinaryDialog.draw()) {
        isoPath.value = m_openBinaryDialog.m_currentPath;
        changed = true;
        std::vector<PCSX::u8string> fileToOpen = m_openBinaryDialog.selected();
        if (!fileToOpen.empty()) {
            m_exeToLoad.set(fileToOpen[0]);
            std::filesystem::path p = fileToOpen[0];
            g_system->log(LogClass::UI, "Scheduling to load %s and soft reseting.\n", p.string());
            g_system->softReset();
        }
    }

    if (m_showDemo) ImGui::ShowDemoWindow();

    ImGui::SetNextWindowPos(ImVec2(10, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1024, 512), ImGuiCond_FirstUseEver);
    if (m_mainVRAMviewer.m_show) m_mainVRAMviewer.draw(this, g_emulator->m_gpu->getVRAMTexture());
    if (m_clutVRAMviewer.m_show) m_clutVRAMviewer.draw(this, g_emulator->m_gpu->getVRAMTexture());
    for (auto& viewer : m_VRAMviewers) {
        if (viewer.m_show) {
            viewer.draw(this, g_emulator->m_gpu->getVRAMTexture());
        }
    }

    if (m_log.m_show) {
        ImGui::SetNextWindowPos(ImVec2(10, 540), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1200, 250), ImGuiCond_FirstUseEver);
        changed |= m_log.draw(this, _("Logs"));
    }

    if (m_luaConsole.m_show) {
        ImGui::SetNextWindowPos(ImVec2(15, 545), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1200, 250), ImGuiCond_FirstUseEver);
        m_luaConsole.draw(_("Lua Console"), this);
    }

    if (m_luaInspector.m_show) {
        ImGui::SetNextWindowPos(ImVec2(20, 550), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1200, 250), ImGuiCond_FirstUseEver);
        m_luaInspector.draw(_("Lua Inspector"), *g_emulator->m_lua, this);
    }
    if (m_luaEditor.m_show) {
        m_luaEditor.draw(_("Lua Editor"), this);
    }
    if (m_events.m_show) {
        m_events.draw(reinterpret_cast<const uint32_t*>(g_emulator->m_mem->m_psxM), _("Kernel events"));
    }
    if (m_handlers.m_show) {
        m_handlers.draw(reinterpret_cast<const uint32_t*>(g_emulator->m_mem->m_psxM), _("Kernel handlers"));
    }
    if (m_kernelLog.m_show) {
        changed |= m_kernelLog.draw(g_emulator->m_cpu.get(), _("Kernel Calls"));
    }
    if (m_callstacks.m_show) {
        m_callstacks.draw(_("Callstacks"), this);
    }

    {
        unsigned counter = 0;
        for (auto& editor : m_mainMemEditors) {
            if (editor.show) {
                ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
                ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
                editor.draw(g_emulator->m_mem->m_psxM, 8 * 1024 * 1024, 0x80000000);
            }
            counter++;
        }
        if (m_parallelPortEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_parallelPortEditor.draw(g_emulator->m_mem->m_psxP, 64 * 1024, 0x1f000000);
        }
        counter++;
        if (m_scratchPadEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_scratchPadEditor.draw(g_emulator->m_mem->m_psxH, 1024, 0x1f800000);
        }
        counter++;
        if (m_hwrEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_hwrEditor.draw(g_emulator->m_mem->m_psxH + 4 * 1024, 8 * 1024, 0x1f801000);
        }
        counter++;
        if (m_biosEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_biosEditor.draw(g_emulator->m_mem->m_psxR, 512 * 1024, 0xbfc00000);
        }
        counter++;
        if (m_vramEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);

            // This const_cast is disgusting but we only use it to satisfy the type system
            // The slice data is indeed treated as read-only
            const Slice vram = g_emulator->m_gpu->getVRAM();
            m_vramEditor.draw(const_cast<void*>(vram.data()), vram.size());
        }
    }

    if (m_memcardManager.m_show) {
        changed |= m_memcardManager.draw(this, _("Memory Card Manager"));
    }

    if (m_registers.m_show) {
        m_registers.draw(this, &PCSX::g_emulator->m_cpu->m_regs, _("Registers"));
    }

    if (m_assembly.m_show) {
        m_assembly.draw(this, &PCSX::g_emulator->m_cpu->m_regs, PCSX::g_emulator->m_mem.get(), _("Assembly"));
    }

    if (m_disassembly.m_show && PCSX::g_emulator->m_cpu->isDynarec()) {
        m_disassembly.draw(this, _("DynaRec Disassembler"));
    }

    if (m_breakpoints.m_show) {
        m_breakpoints.draw(_("Breakpoints"));
    }

    if (m_memoryObserver.m_show) {
        m_memoryObserver.draw(_("Memory Observer"));
    }

    if (m_typedDebugger.m_show) {
        m_typedDebugger.draw(_("Typed Debugger"), this);
    }

    if (m_showAbout) changed |= about();
    if (m_showInterruptsScaler) interruptsScaler();

    if (m_outputShaderEditor.m_show && m_outputShaderEditor.draw(this, _("Output Video"))) {
        // maybe throttle this?
        m_outputShaderEditor.compile(this);
    }

    if (m_offscreenShaderEditor.m_show && m_offscreenShaderEditor.draw(this, _("Offscreen Render"))) {
        // maybe throttle this?
        m_offscreenShaderEditor.compile(this);
    }

    if (m_sio1.m_show) {
        m_sio1.draw(this, &PCSX::g_emulator->m_sio1->m_regs, _("SIO1 Debug"));
    }

    if (m_showCfg) changed |= configure();
    if (g_emulator->m_spu->m_showCfg) changed |= g_emulator->m_spu->configure();
    g_emulator->m_spu->debug();
    changed |= g_emulator->m_pads->configure(this);

    if (g_emulator->m_gpu->m_showCfg) changed |= g_emulator->m_gpu->configure();
    if (g_emulator->m_gpu->m_showDebug) g_emulator->m_gpu->debug();

    if (m_showUiCfg) {
        if (ImGui::Begin(_("UI Configuration"), &m_showUiCfg)) {
            changed |= showThemes();
            bool needFontReload = false;
            {
                std::string currentLocale = g_system->localeName();
                if (currentLocale.length() == 0) currentLocale = "English";
                if (ImGui::BeginCombo(_("Locale"), currentLocale.c_str())) {
                    if (ImGui::Selectable("English", currentLocale == "English")) {
                        g_system->activateLocale("English");
                        g_emulator->settings.get<Emulator::SettingLocale>() = "English";
                        needFontReload = true;
                    }
                    for (auto& l : g_system->localesNames()) {
                        if (ImGui::Selectable(l.c_str(), currentLocale == l)) {
                            g_system->activateLocale(l);
                            g_emulator->settings.get<Emulator::SettingLocale>() = l;
                            needFontReload = true;
                        }
                    }
                    ImGui::EndCombo();
                }
                if (ImGui::Button(_("Reload locales"))) {
                    g_system->loadAllLocales();
                    g_system->activateLocale(currentLocale);
                }
            }
            needFontReload |= ImGui::SliderInt(_("Main Font Size"), &settings.get<MainFontSize>().value, 8, 48);
            needFontReload |= ImGui::SliderInt(_("Mono Font Size"), &settings.get<MonoFontSize>().value, 8, 48);
            bool ratioChanged =
                ImGui::Checkbox(_("Use Widescreen Aspect Ratio"), &settings.get<WidescreenRatio>().value);
            ShowHelpMarker(_(R"(Sets the output screen ratio to 16:9 instead of 4:3.

Note that this setting is NOT the popular hack
to force games into widescreen mode, but rather an
emulation of the fact users could change their
TV sets to be in 16:9 mode instead of 4:3.

Some games have a "wide screen" rendering setting,
which changes the rendering of the game accordingly,
and requires the user to change the settings of
their TV set to match the aspect ratio of the game.)"));
            changed |= needFontReload | ratioChanged;
            if (needFontReload) m_reloadFonts = true;
            if (ratioChanged) m_setupScreenSize = true;
        }
        ImGui::End();
    }

    if (m_showSysCfg) {
        if (ImGui::Begin(_("System Configuration"), &m_showSysCfg)) {
            changed |=
                ImGui::Checkbox(_("Preload Disk Image files"), &emuSettings.get<Emulator::SettingFullCaching>().value);
            changed |= ImGui::Checkbox(_("Enable Auto Update"), &emuSettings.get<Emulator::SettingAutoUpdate>().value);
        }
        ImGui::End();
    }

    if (!g_system->getVersion().failed() && !emuSettings.get<Emulator::SettingShownAutoUpdateConfig>().value) {
        if (ImGui::Begin(_("Update configuration"), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextUnformatted((_(R"(PCSX-Redux can automatically update itself.

If you enable the auto update option, it will check for new updates
on startup. No personal data nor identifiable token is sent for this
process, but Microsoft might still keep and record information such
as your IP address.

If an update is available, you will get prompted to download and
install it. You can still download versions of PCSX-Redux as usual
from its website.

If you want to change this setting later, you can go to the
Configuration -> System menu.)")));
            if (ImGui::Button(_("Enable auto update"))) {
                emuSettings.get<Emulator::SettingShownAutoUpdateConfig>().value = true;
                emuSettings.get<Emulator::SettingAutoUpdate>().value = true;
                changed = true;
            }
            ImGui::SameLine();
            if (ImGui::Button(_("No thanks"))) {
                emuSettings.get<Emulator::SettingShownAutoUpdateConfig>().value = true;
                changed = true;
            }
        }
        ImGui::End();
    }

    if (m_updateAvailable) {
        if (ImGui::Begin(_("Update available"), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            if (m_update.canFullyApply()) {
                ImGui::TextUnformatted((_(R"(An update is available.
Click 'Update' to download and apply the update.
PCSX-Redux will automatically restart to apply it.

Click 'Download' to use your browser to download
the update and manually apply it.)")));
            } else {
                ImGui::TextUnformatted((_(R"(An update is available.
Click 'Update' to download it. While the update can be
downloaded, it won't be applied automatically. You will
have to install it manually, the way you previously did.
PCSX-Redux will quit once the update is downloaded.

Click 'Download' to use your browser to download
the update and manually apply it.)")));
            }
            ImGui::ProgressBar(m_update.progress());
            if (!m_updateDownloading) {
                if (ImGui::Button(_("Update"))) {
                    m_updateDownloading = true;
                    bool started = m_update.downloadAndApplyUpdate(
                        g_system->getVersion(),
                        [this](bool success) {
                            m_updateAvailable = false;
                            m_updateDownloading = false;
                            if (success) {
                                m_update.applyUpdate(g_system->getBinDir());
                                g_system->quit();
                            } else {
                                addNotification(
                                    _("An error has occured while downloading\nand/or applying the update."));
                            }
                        },
                        g_system->getLoop());
                    if (!started) {
                        addNotification(_("An error has occured while downloading\nand/or applying the update."));
                        m_updateAvailable = false;
                        m_updateDownloading = false;
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button(_("Download"))) {
                    m_updateDownloading = true;
                    bool started = m_update.getDownloadUrl(
                        g_system->getVersion(),
                        [this](std::string url) {
                            openUrl(url);
                            m_updateDownloading = false;
                        },
                        g_system->getLoop());
                    if (!started) {
                        addNotification(_("An error has occured while downloading the update."));
                        m_updateAvailable = false;
                        m_updateDownloading = false;
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button(_("Cancel"))) {
                    m_updateAvailable = false;
                }
            }
        }
        ImGui::End();
    }

    if (m_showHandles) {
        if (ImGui::Begin(_("UvFiles"), &m_showHandles)) {
            std::string rate;
            byteRateToString(UvFile::getReadRate(), rate);
            ImGui::Text(_("Read rate: %s"), rate.c_str());
            byteRateToString(UvFile::getWriteRate(), rate);
            ImGui::Text(_("Write rate: %s"), rate.c_str());
            byteRateToString(UvFile::getDownloadRate(), rate);
            ImGui::Text(_("Download rate: %s"), rate.c_str());
            if (ImGui::BeginTable("UvFiles", 2)) {
                ImGui::TableSetupColumn(_("Caching"));
                ImGui::TableSetupColumn(_("Filename"));
                ImGui::TableHeadersRow();
                UvThreadOp::iterateOverAllOps([](UvThreadOp* f) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (f->caching()) {
                        ImGui::ProgressBar(f->cacheProgress());
                    } else {
                        std::string label = fmt::format("Cache##{}", reinterpret_cast<void*>(f));
                        auto canCache = f->canCache();
                        if (!canCache) {
                            ImGui::BeginDisabled();
                        }
                        if (ImGui::Button(label.c_str()) && canCache) {
                            f->startCaching();
                        }
                        if (!canCache) {
                            ImGui::EndDisabled();
                        }
                    }
                    ImGui::TableSetColumnIndex(1);
                    File* actual = dynamic_cast<File*>(f);
                    ImGui::TextUnformatted(actual->filename().string().c_str());
                });
                ImGui::EndTable();
            }
        }
        ImGui::End();
    }

    auto L = *g_emulator->m_lua;
    L.getfield("DrawImguiFrame", LUA_GLOBALSINDEX);
    if (!L.isnil()) {
        ScopedOnlyLog(this);
        try {
            L.pcall();
            bool gotGLerror = false;
            for (const auto& error : m_glErrors) {
                m_luaConsole.addError(error);
                if (m_args.get<bool>("lua_stdout", false)) {
                    fprintf(stderr, "%s\n", error.c_str());
                }
                gotGLerror = true;
            }
            m_glErrors.clear();
            if (gotGLerror) throw("OpenGL error while running Lua code");
        } catch (...) {
            L.push("DrawImguiFrame");
            L.push();
            L.settable(LUA_GLOBALSINDEX);
        }
    } else {
        L.pop();
    }
    m_notifier.draw();

    ImGui::Render();
    glViewport(0, 0, w, h);
    if (m_fullscreenRender) {
        glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
    } else {
        glClearColor(m_backgroundColor.x, m_backgroundColor.y, m_backgroundColor.z, m_backgroundColor.w);
    }
    glClearDepthf(0.0f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        glfwMakeContextCurrent(m_window);
    }

    glfwSwapBuffers(m_window);

    if (changed) saveCfg();
    if (m_gotImguiUserError) {
        g_system->log(LogClass::UI, "Got ImGui User Error: %s\n", m_imguiUserError.c_str());
        m_gotImguiUserError = false;
        L.push();
        L.setfield("DrawImguiFrame", LUA_GLOBALSINDEX);
    }

    FrameMark
}

bool PCSX::GUI::configure() {
    bool changed = false;
    bool selectBiosDialog = false;
    bool showDynarecDebugWarning = false;
    bool showDynarecWarning = false;
    auto& settings = g_emulator->settings;
    auto& debugSettings = settings.get<Emulator::SettingDebugSettings>();

    ImGui::SetNextWindowPos(ImVec2(50, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 500), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(_("Emulation Configuration"), &m_showCfg)) {
        if (ImGui::SliderInt(_("Idle Swap Interval"), &m_idleSwapInterval, 0, 10)) {
            changed = true;
            if (!g_system->running()) glfwSwapInterval(m_idleSwapInterval);
        }
        ImGui::Separator();
        if (ImGui::Button(_("Reset Scaler"))) {
            changed = true;
            settings.get<Emulator::SettingScaler>() = 100;
        }
        float scale = settings.get<Emulator::SettingScaler>();
        scale /= 100.0f;
        changed |= ImGui::SliderFloat(_("Speed Scaler"), &scale, 0.1f, 25.0f);
        settings.get<Emulator::SettingScaler>() = scale * 100.0f;
        changed |= ImGui::Checkbox(_("Enable XA decoder"), &settings.get<Emulator::SettingXa>().value);
        changed |= ImGui::Checkbox(_("Always enable SPU IRQ"), &settings.get<Emulator::SettingSpuIrq>().value);
        changed |= ImGui::Checkbox(_("Decode MDEC videos in B&W"), &settings.get<Emulator::SettingBnWMdec>().value);
        if (ImGui::Checkbox(_("Dynarec CPU"), &settings.get<Emulator::SettingDynarec>().value)) {
            changed = true;
            showDynarecWarning = true;
            if (debugSettings.get<PCSX::Emulator::DebugSettings::Debug>() && settings.get<Emulator::SettingDynarec>()) {
                showDynarecDebugWarning = true;
            }
        }

        ShowHelpMarker(_(R"(Activates the dynamic recompiler CPU core.
It is significantly faster than the interpreted CPU,
however it doesn't play nicely with the debugger.
Changing this setting requires a reboot to take effect.
The dynarec core isn't available for all CPUs, so
this setting may not have any effect for you.)"));
        bool memChanged = ImGui::Checkbox(_("8MB"), &settings.get<Emulator::Setting8MB>().value);
        ShowHelpMarker(_(R"(Emulates an installed 8MB system,
instead of the normal 2MB. Useful for working
with development binaries and games.)"));
        changed |=
            ImGui::Checkbox(_("OpenGL GPU *ALPHA STATE*"), &settings.get<Emulator::SettingHardwareRenderer>().value);
        ShowHelpMarker(_(R"(Enables the OpenGL GPU renderer.
This is not recommended for normal use at the moment,
as it is not fully implemented yet. It is recommended
to use the software renderer instead. Requires a restart
when changing this setting.)"));

        if (memChanged) {
            changed = true;
            g_emulator->m_mem->setLuts();
        }

        {
            static const std::function<const char*()> types[] = {
                []() { return _("Auto"); },
                []() { return _("NTSC"); },
                []() { return _("PAL"); },
            };
            auto& autodetect = settings.get<Emulator::SettingAutoVideo>().value;
            auto& type = settings.get<Emulator::SettingVideo>().value;
            if (ImGui::BeginCombo(_("System Type"), types[autodetect ? 0 : (type + 1)]())) {
                if (ImGui::Selectable(types[0](), autodetect)) {
                    changed = true;
                    autodetect = true;
                }
                if (ImGui::Selectable(types[1](), !autodetect && (type == PCSX::Emulator::PSX_TYPE_NTSC))) {
                    changed = true;
                    type = PCSX::Emulator::PSX_TYPE_NTSC;
                    autodetect = false;
                }
                if (ImGui::Selectable(types[2](), !autodetect && (type == PCSX::Emulator::PSX_TYPE_PAL))) {
                    changed = true;
                    type = PCSX::Emulator::PSX_TYPE_PAL;
                    autodetect = false;
                }
                ImGui::EndCombo();
            }
        }

        changed |= ImGui::Checkbox(_("Fast boot"), &settings.get<Emulator::SettingFastBoot>().value);
        ShowHelpMarker(_(R"(This will cause the BIOS to skip the shell,
which may include additional checks.
Also will make the boot time substantially
faster by not displaying the logo.)"));
        auto bios = settings.get<Emulator::SettingBios>().string();
        ImGui::InputText(_("BIOS file"), const_cast<char*>(reinterpret_cast<const char*>(bios.c_str())), bios.length(),
                         ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        selectBiosDialog = ImGui::Button("...");
        if (ImGui::Checkbox(_("Enable Debugger"), &debugSettings.get<Emulator::DebugSettings::Debug>().value)) {
            changed = true;
            if (debugSettings.get<PCSX::Emulator::DebugSettings::Debug>() && settings.get<Emulator::SettingDynarec>()) {
                showDynarecDebugWarning = true;
            }
        }

        ShowHelpMarker(_(R"(This will enable the usage of various breakpoints
throughout the execution of mips code. Enabling this
can slow down emulation to a noticable extend.)"));
        if (ImGui::Checkbox(_("Enable GDB Server"), &debugSettings.get<Emulator::DebugSettings::GdbServer>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::GdbServer>()) {
                g_emulator->m_gdbServer->startServer(g_system->getLoop(),
                                                     debugSettings.get<Emulator::DebugSettings::GdbServerPort>());
            } else {
                g_emulator->m_gdbServer->stopServer();
            }
        }
        ShowHelpMarker(_(R"(This will activate a gdb-server that you can
connect to with any gdb-remote compliant client.
You also need to enable the debugger.)"));
        changed |=
            ImGui::Checkbox(_("GDB send manifest"), &debugSettings.get<Emulator::DebugSettings::GdbManifest>().value);
        ShowHelpMarker(_(R"(Enables sending the processor's manifest
from the gdb server. Keep this enabled, unless
you want to connect IDA to this server, as it
has a bug in its manifest parser.)"));
        auto& currentGdbLog = debugSettings.get<Emulator::DebugSettings::GdbLogSetting>().value;
        auto currentName = magic_enum::enum_name(currentGdbLog);

        if (ImGui::BeginCombo(_("PCSX Logs to GDB"), currentName.data())) {
            for (auto v : magic_enum::enum_values<Emulator::DebugSettings::GdbLog>()) {
                bool selected = (v == currentGdbLog);
                auto name = magic_enum::enum_name(v);
                if (ImGui::Selectable(name.data(), selected)) {
                    currentGdbLog = v;
                    changed = true;
                }
                if (selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }

        changed |=
            ImGui::InputInt(_("GDB Server Port"), &debugSettings.get<Emulator::DebugSettings::GdbServerPort>().value);
        changed |=
            ImGui::Checkbox(_("GDB Server Trace"), &debugSettings.get<Emulator::DebugSettings::GdbServerTrace>().value);
        ShowHelpMarker(_(R"(The GDB server will start tracing its
protocol into the logs, which can be helpful to debug
the gdb server system itself.)"));
        if (ImGui::Checkbox(_("Enable Web Server"), &debugSettings.get<Emulator::DebugSettings::WebServer>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::WebServer>()) {
                g_emulator->m_webServer->startServer(g_system->getLoop(),
                                                     debugSettings.get<Emulator::DebugSettings::WebServerPort>());
            } else {
                g_emulator->m_webServer->stopServer();
            }
        }
        ShowHelpMarker(_(R"(This will activate a web-server, that you can
query using a REST api. See the wiki for details.
The debugger might be required in some cases.)"));
        changed |=
            ImGui::InputInt(_("Web Server Port"), &debugSettings.get<Emulator::DebugSettings::WebServerPort>().value);
        if (ImGui::Checkbox(_("Enable SIO1 Server"), &debugSettings.get<Emulator::DebugSettings::SIO1Server>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::SIO1Server>()) {
                g_emulator->m_sio1Server->startServer(g_system->getLoop(),
                                                      debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>());
            } else {
                g_emulator->m_sio1Server->stopServer();
            }
        }
        ShowHelpMarker(_(R"(This will activate a tcp server, that will
relay information between tcp and sio1.
See the wiki for details.)"));
        changed |=
            ImGui::InputInt(_("SIO1 Server Port"), &debugSettings.get<Emulator::DebugSettings::SIO1ServerPort>().value);
        if (ImGui::Checkbox(_("Enable SIO1 Client"), &debugSettings.get<Emulator::DebugSettings::SIO1Client>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::SIO1Client>()) {
                g_emulator->m_sio1Client->startClient(
                    std::string_view(g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                         .get<Emulator::DebugSettings::SIO1ClientHost>()
                                         .value),
                    g_emulator->settings.get<Emulator::SettingDebugSettings>()
                        .get<Emulator::DebugSettings::SIO1ClientPort>());
            } else {
                g_emulator->m_sio1Client->stopClient();
            }
        }
        ShowHelpMarker(_(R"(This will activate a tcp client, that can connect
to another PCSX-Redux server to relay information between tcp and sio1.
See the wiki for details.)"));
        changed |=
            ImGui::InputText(_("SIO1 Client Host"), &debugSettings.get<Emulator::DebugSettings::SIO1ClientHost>().value,
                             ImGuiInputTextFlags_CharsDecimal);
        changed |=
            ImGui::InputInt(_("SIO1 Client Port"), &debugSettings.get<Emulator::DebugSettings::SIO1ClientPort>().value);

        auto& currentSIO1Mode = debugSettings.get<Emulator::DebugSettings::SIO1ModeSetting>().value;
        auto currentSIO1Name = magic_enum::enum_name(currentSIO1Mode);
        if (ImGui::Button(_("Reset SIO"))) {
            g_emulator->m_sio1->reset();
        }

        const bool enableReconnect = debugSettings.get<Emulator::DebugSettings::SIO1Client>() &&
                                     !g_emulator->m_sio1->connecting() && g_emulator->m_sio1->fifoError();

        if (!enableReconnect) {
            ImGui::BeginDisabled();
        }

        if (ImGui::Button(_("Reconnect"))) {
            g_emulator->m_sio1Client->reconnect(
                std::string_view(g_emulator->settings.get<Emulator::SettingDebugSettings>()
                                     .get<Emulator::DebugSettings::SIO1ClientHost>()
                                     .value),
                g_emulator->settings.get<Emulator::SettingDebugSettings>()
                    .get<Emulator::DebugSettings::SIO1ClientPort>());
        }

        if (!enableReconnect) {
            ImGui::EndDisabled();
        }

        if (ImGui::BeginCombo(_("SIO1Mode"), currentSIO1Name.data())) {
            for (auto v : magic_enum::enum_values<Emulator::DebugSettings::SIO1Mode>()) {
                bool selected = (v == currentSIO1Mode);
                auto name = magic_enum::enum_name(v);
                if (ImGui::Selectable(name.data(), selected)) {
                    currentSIO1Mode = v;
                    changed = true;
                }
                if (selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
    }
    ImGui::End();

    if (selectBiosDialog) m_selectBiosDialog.openDialog();
    if (m_selectBiosDialog.draw()) {
        std::vector<PCSX::u8string> fileToOpen = m_selectBiosDialog.selected();
        if (!fileToOpen.empty()) {
            settings.get<Emulator::SettingBios>().value = fileToOpen[0];
            changed = true;
        }
    }

    if (showDynarecDebugWarning && showDynarecWarning) {
        addNotification(R"(Debugger and dynarec enabled at the same time.
Consider turning either one off, otherwise
debugging features may not work. Additionally,
changing the dynarec option requires a restart
of the emulator to take effect.)");
    } else if (showDynarecDebugWarning) {
        addNotification(R"(Debugger and dynarec enabled at the same time.
Consider turning either one off, otherwise
debugging features may not work.)");
    } else if (showDynarecWarning) {
        addNotification(R"(Toggling the Dynarec option requires a restart
of the emulator to take effect.)");
    }
    return changed;
}

void PCSX::GUI::interruptsScaler() {
    static const char* names[] = {
        "SIO",      "SIO1",        "CDR",         "CDR Read", "GPU DMA", "MDEC Out DMA",       "SPU DMA",
        "GPU Busy", "MDEC In DMA", "GPU OTC DMA", "CDR DMA",  "SPU",     "CDR Decoded Buffer", "CDR Lid Seek",
        "CDR Play",
    };
    if (ImGui::Begin(_("Interrupt Scaler"), &m_showInterruptsScaler)) {
        if (ImGui::Button(_("Reset all"))) {
            for (auto& scale : g_emulator->m_cpu->m_interruptScales) {
                scale = 1.0f;
            }
        }
        unsigned counter = 0;
        for (auto& scale : g_emulator->m_cpu->m_interruptScales) {
            ImGui::SliderFloat(names[counter], &scale, 0.0f, 100.0f, "%.3f", ImGuiSliderFlags_AlwaysClamp);
            counter++;
        }
    }
    ImGui::End();
}

bool PCSX::GUI::showThemes() {
    static const std::function<const char*()> imgui_themes[] = {
        []() { return _("Default theme"); }, []() { return _("Classic"); }, []() { return _("Light"); },
        []() { return _("Cherry"); },        []() { return _("Mono"); },    []() { return _("Dracula"); },
        []() { return _("Olive"); },
    };
    auto changed = false;
    auto& currentTheme = g_emulator->settings.get<Emulator::SettingGUITheme>().value;

    if (ImGui::BeginCombo(_("Themes"), imgui_themes[currentTheme](), ImGuiComboFlags_HeightLarge)) {
        for (int n = 0; n < IM_ARRAYSIZE(imgui_themes); n++) {
            bool selected = (currentTheme == n);
            if (ImGui::Selectable(imgui_themes[n](), selected)) {
                currentTheme = n;
                changed = true;
                applyTheme(n);
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    return changed;
}

bool PCSX::GUI::about() {
    bool changed = false;

    ImGui::SetNextWindowPos(ImVec2(200, 100), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(880, 600), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(_("About"), &m_showAbout)) {
        ImGui::Text("PCSX-Redux");
        ImGui::Separator();
        auto someString = [](const char* str, GLenum index) {
            const char* value = (const char*)glGetString(index);
            ImGui::TextWrapped("%s: %s", str, value);
        };
        if (ImGui::BeginTabBar("AboutTabs", ImGuiTabBarFlags_None)) {
            if (ImGui::BeginTabItem(_("Version"))) {
                auto& version = g_system->getVersion();
                if (version.failed()) {
                    ImGui::BeginDisabled();
                }
                if (ImGui::Button(_("Copy to clipboard"))) {
                    clip::set_text(fmt::format("Version: {}\nChangeset: {}\nDate & time: {:%Y-%m-%d %H:%M:%S}",
                                               version.version, version.changeset, fmt::localtime(version.timestamp)));
                }
                if (version.failed()) {
                    ImGui::EndDisabled();
                    ImGui::TextUnformatted(_("No version information.\n\nProbably built from source."));
                } else {
                    ImGui::Text(_("Version: %s"), version.version.c_str());
                    ImGui::Text(_("Changeset: %s"), version.changeset.c_str());
                    std::tm tm = fmt::localtime(version.timestamp);
                    std::string timestamp = fmt::format("{:%Y-%m-%d %H:%M:%S}", tm);
                    ImGui::Text(_("Date & time: %s"), timestamp.c_str());
                }
                ImGui::EndTabItem();
            }
            ImGuiTabItemFlags flag = 0;
            if (m_aboutSelectAuthors) {
                flag |= ImGuiTabItemFlags_SetSelected;
                m_aboutSelectAuthors = false;
            }
            if (ImGui::BeginTabItem(_("Authors"), nullptr, flag)) {
                ImGui::BeginChild("Authors", ImVec2(0, 0), true);
                ImGui::TextUnformatted(
#include "AUTHORS"
                );
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Licenses"))) {
                ImGui::BeginChild("Licenses", ImVec2(0, 0), true);

                static MarkDown md({{"AUTHORS", [this]() { m_aboutSelectAuthors = true; }}});
                std::string_view text =
#include "LICENSES.md"
                    ;
                md.print(text);

                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("OpenGL information"))) {
                if (m_reportGLErrors) {
                    ImGui::TextUnformatted(_("OpenGL error reporting: enabled"));
                } else {
                    ImGui::TextUnformatted(_("OpenGL error reporting: disabled"));
                    if (!glDebugMessageCallback) {
                        ShowHelpMarker(
                            _("OpenGL error reporting has been disabled because your OpenGL driver is too old. Error "
                              "reporting requires at least OpenGL 4.3. Please update your graphics drivers, or "
                              "contact your GPU vendor for up to date OpenGL drivers. Disabled OpenGL error reporting "
                              "won't have a negative impact on the performances of this software, but user code such "
                              "as the shader editor won't be able to properly report problems accurately."));
                    }
                }

                changed |= ImGui::Checkbox(_("Enable OpenGL error reporting"),
                                           &g_emulator->settings.get<Emulator::SettingGLErrorReporting>().value);
                ShowHelpMarker(
                    _("OpenGL error reporting is necessary for properly reporting OpenGL problems. "
                      "However it requires OpenGL 4.3+ and might have performance repercussions on "
                      "some computers. (Requires a restart of the emulator)"));
                changed |= ImGui::SliderInt(
                    _("OpenGL error reporting severity"),
                    &g_emulator->settings.get<Emulator::SettingGLErrorReportingSeverity>().value, 0, 3);

                ImGui::Text(_("Core profile: %s"), m_hasCoreProfile ? _("yes") : _("no"));
                someString(_("Vendor"), GL_VENDOR);
                someString(_("Renderer"), GL_RENDERER);
                someString(_("Version"), GL_VERSION);
                someString(_("Shading language version"), GL_SHADING_LANGUAGE_VERSION);
                GLint n, i;
                glGetIntegerv(GL_NUM_EXTENSIONS, &n);
                ImGui::TextUnformatted(_("Extensions:"));
                ImGui::BeginChild("GLextensions", ImVec2(0, 0), true);
                for (i = 0; i < n; i++) {
                    const char* extension = (const char*)glGetStringi(GL_EXTENSIONS, i);
                    ImGui::Text("%s", extension);
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
    return changed;
}

void PCSX::GUI::update(bool vsync) {
    glDisable(GL_SCISSOR_TEST);
    endFrame();
    startFrame();
    // At all times, either the emulated GPU core or the GUI have full control of the host GPU & the GL context
    // We do this by having the emulated GPU have it most of the time, then let the GUI steal it when it needs it.
    // And in the line afterwards, the GUI gives the GL context back to the emulated GPU.
    g_emulator->m_gpu->setOpenGLContext();
    if (vsync && m_breakOnVSync) {
        g_system->pause();
    }
}

void PCSX::GUI::shellReached() {
    auto& regs = g_emulator->m_cpu->m_regs;
    uint32_t oldPC = regs.pc;
    if (g_emulator->settings.get<PCSX::Emulator::SettingFastBoot>()) regs.pc = regs.GPR.n.ra;

    if (m_exeToLoad.empty()) return;
    PCSX::u8string filename = m_exeToLoad.get();
    std::filesystem::path p = filename;

    g_system->log(LogClass::UI, "Hijacked shell, loading %s...\n", p.string());
    bool success = false;
    auto backupPC = regs.pc;
    try {
        success = BinaryLoader::load(filename);
    } catch (std::exception& e) {
        g_system->log(LogClass::UI, "Failed to load %s: %s\n", p.string(), e.what());
        regs.pc = backupPC;
    } catch (...) {
        g_system->log(LogClass::UI, "Failed to load %s: unknown error\n", p.string());
        regs.pc = backupPC;
    }
    if (success) {
        g_system->log(LogClass::UI, "Successful: new PC = %08x...\n", regs.pc);
    }

    if (m_exeToLoad.hasToPause()) {
        g_system->pause();
    }

    if (oldPC != regs.pc) {
        g_emulator->m_callStacks->potentialRA(regs.pc, regs.GPR.n.sp);
        g_emulator->m_debug->updatedPC(regs.pc);
    }
}

void PCSX::GUI::magicOpen(const char* pathStr) {
    // Try guessing what we're opening using extension only.
    // Doing magic guesses might be an option, but that's exhausting right now. Maybe later.
    std::filesystem::path path(pathStr);

    static const std::vector<std::string> exeExtensions = {
        "EXE", "PSX", "PS-EXE", "PSF", "MINIPSF", "PSFLIB", "CPE", "ELF",
    };

    const auto& extensionPath = path.extension().string();

    char* extension = (char*)malloc(extensionPath.length());
    for (int i = 1; i < extensionPath.length(); i++) {
        extension[i - 1] = toupper(extensionPath[i]);
    }
    extension[extensionPath.length() - 1] = 0;

    if (std::find(exeExtensions.begin(), exeExtensions.end(), extension) != exeExtensions.end()) {
        m_exeToLoad.set(path.u8string());
        g_system->log(LogClass::UI, "Scheduling to load %s and soft reseting.\n", path.string());
        g_system->softReset();
    } else {
        PCSX::g_emulator->m_cdrom->setIso(new CDRIso(pathStr));
        PCSX::g_emulator->m_cdrom->check();
    }

    free(extension);
}

std::string PCSX::GUI::buildSaveStateFilename(int i) {
    // the ID of the game. Every savestate is marked with the ID of the game it's from.
    const auto gameID = g_emulator->m_cdrom->getCDRomID();

    // Check if the game has a non-NULL ID or a game hasn't been loaded. Some stuff like PS-X
    // EXEs don't have proper IDs
    if (!gameID.empty()) {
        // For games with an ID of SLUS00213 for example, this will generate a state named
        // SLUS00213.sstate
        return fmt::format("{}.sstate{}", gameID, i);
    } else {
        // For games without IDs, identify them via filename
        const auto& iso = PCSX::g_emulator->m_cdrom->getIso()->getIsoPath().filename();
        const auto lastFile = iso.empty() ? "BIOS" : iso.string();
        return fmt::format("{}.sstate{}", lastFile, i);
    }
}

void PCSX::GUI::saveSaveState(const std::filesystem::path& filename) {
    // TODO: yeet this to libuv's threadpool.
    ZWriter save(new UvFile(filename, FileOps::TRUNCATE), ZWriter::GZIP);
    if (!save.failed()) save.writeString(SaveStates::save());
    save.close();
}

void PCSX::GUI::loadSaveState(const std::filesystem::path& filename) {
    ZReader save(new PosixFile(filename));
    if (save.failed()) return;
    std::ostringstream os;
    constexpr unsigned buff_size = 1 << 16;
    char* buff = new char[buff_size];
    bool error = false;

    while (!save.eof()) {
        auto cnt = save.read(buff, buff_size);
        if (cnt == 0) break;
        if (cnt < 0) {
            error = true;
            break;
        }
        os.write(buff, cnt);
    }

    save.close();
    delete[] buff;

    if (!error) SaveStates::load(os.str());
};

void PCSX::GUI::byteRateToString(float rate, std::string& str) {
    if (rate >= 1000000000) {
        str = fmt::format("{:.2f} GB/s", rate / 1000000000);
    } else if (rate >= 1000000) {
        str = fmt::format("{:.2f} MB/s", rate / 1000000);
    } else if (rate >= 1000) {
        str = fmt::format("{:.2f} KB/s", rate / 1000);
    } else {
        str = fmt::format("{:.2f} B/s", rate);
    }
}
