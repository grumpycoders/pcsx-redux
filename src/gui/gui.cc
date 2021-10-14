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

#define GLFW_INCLUDE_NONE
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_STATIC
#define STBI_ASSERT(x) assert(x)
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STBI_ONLY_PNG
#include "gui/gui.h"

#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <assert.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <type_traits>
#include <unordered_set>

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
#include "core/sstate.h"
#include "core/web-server.h"
#include "flags.h"
#include "gpu/soft/externals.h"
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
#include "stb/stb_image.h"
#include "tracy/Tracy.hpp"
#include "zstr.hpp"

#ifdef _WIN32
extern "C" {
_declspec(dllexport) DWORD NvOptimusEnablement = 1;
_declspec(dllexport) DWORD AmdPowerXpressRequestHighPerformance = 1;
}
#endif

using json = nlohmann::json;

static std::function<void(const char*)> s_imguiUserErrorFunctor = nullptr;
extern "C" void pcsxStaticImguiUserError(const char* msg) {
    if (s_imguiUserErrorFunctor) {
        s_imguiUserErrorFunctor(msg);
    } else {
        throw std::runtime_error(msg);
    }
}

extern "C" void pcsxStaticImguiAssert(int exp, const char* msg) {
    if (!exp) throw std::runtime_error(msg);
}

PCSX::GUI* PCSX::GUI::s_gui = nullptr;

void PCSX::GUI::bindVRAMTexture() {
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    checkGL();
}

void PCSX::GUI::checkGL() {
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        throw std::runtime_error("Got OpenGL error");
    }
}

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

static PCSX::GUI* s_this = nullptr;

static void drop_callback(GLFWwindow* window, int count, const char** paths) {
    if (count != 1) return;
    s_this->magicOpen(paths[0]);
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

void PCSX::GUI::init() {
    int result;
    LoadImguiBindings(g_emulator->m_lua->getState());
    s_imguiUserErrorFunctor = [this](const char* msg) {
        m_gotImguiUserError = true;
        m_imguiUserError = msg;
    };
    m_luaConsole.setCmdExec([this](const std::string& cmd) {
        try {
            g_emulator->m_lua->load(cmd, "console", false);
            g_emulator->m_lua->pcall();
            bool gotGLerror = false;
            GLenum glError = GL_NO_ERROR;
            while ((glError = glGetError()) != GL_NO_ERROR) {
                std::string msg = "glError: ";
                msg += glErrorToString(glError);
                m_luaConsole.addError(msg);
                if (m_args.get<bool>("lua_stdout", false)) {
                    fprintf(stderr, "%s\n", msg.c_str());
                }
                gotGLerror = true;
            }
        } catch (std::exception& e) {
            m_luaConsole.addError(e.what());
            if (m_args.get<bool>("lua_stdout", false)) {
                fprintf(stderr, "%s\n", e.what());
            }
        }
    });
    auto printer = [this](Lua L, bool error) -> int {
        int n = L.gettop();
        std::string s;

        for (int i = 1; i <= n; i++) {
            if (i > 1) s += " ";
            if (L.isstring(i)) {
                s += L.tostring(i);
            } else {
                L.getglobal("tostring");
                L.copy(i);
                L.pcall(1);
                s += L.tostring(-1);
                L.pop();
            }
        }
        if (error) {
            m_luaConsole.addError(s);
        } else {
            m_luaConsole.addLog(s);
        }
        if (m_args.get<bool>("lua_stdout", false)) {
            if (error) {
                fprintf(stderr, "%s\n", s.c_str());
            } else {
                fprintf(stdout, "%s\n", s.c_str());
            }
        }
        return 0;
    };
    g_emulator->m_lua->declareFunc("print", [printer](Lua L) { return printer(L, false); });
    g_emulator->m_lua->declareFunc("printError", [printer](Lua L) { return printer(L, true); });
    g_emulator->m_lua->load(R"(
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

    glfwSetErrorCallback(
        [](int error, const char* description) { fprintf(stderr, "Glfw Error %d: %s\n", error, description); });
    if (!glfwInit()) {
        abort();
    }

    m_listener.listen<Events::ExecutionFlow::ShellReached>([this](const auto& event) { shellReached(); });
    m_listener.listen<Events::ExecutionFlow::Pause>(
        [this](const auto& event) { glfwSwapInterval(m_idleSwapInterval); });
    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) { glfwSwapInterval(0); });

    auto monitor = glfwGetPrimaryMonitor();

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    m_hasCoreProfile = true;

    m_window = glfwCreateWindow(1280, 800, "PCSX-Redux", nullptr, nullptr);

    if (!m_window) {
        glfwDefaultWindowHints();
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
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

    Resources::loadIcon([this](const uint8_t* data, uint32_t size) {
        int x, y, comp;
        stbi_uc* img;
        img = stbi_load_from_memory(data, size, &x, &y, &comp, 4);
        if (!img) return;
        if (comp != 4) {
            stbi_image_free(img);
            return;
        }
        GLFWimage image;
        image.width = x;
        image.height = y;
        image.pixels = img;
        glfwSetWindowIcon(m_window, 1, &image);
        stbi_image_free(img);
    });

    result = gl3wInit();
    if (result) {
        throw std::runtime_error("Unable to initialize OpenGL layer. Check OpenGL drivers.");
    }

    LuaFFI::open_gl(g_emulator->m_lua.get());

    // Setup ImGui binding
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    {
        io.IniFilename = nullptr;
        std::ifstream cfg("pcsx.json");
        auto& emuSettings = PCSX::g_emulator->settings;
        auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
        json j;
        if (cfg.is_open() && !m_args.get<bool>("safe")) {
            try {
                cfg >> j;
            } catch (...) {
            }
            if ((j.count("imgui") == 1) && j["imgui"].is_string()) {
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
            if (!windowSizeX) {
                windowSizeX = 1280;
            }
            if (!windowSizeY) {
                windowSizeY = 800;
            }

            glfwSetWindowPos(m_window, settings.get<WindowPosX>(), settings.get<WindowPosY>());
            glfwSetWindowSize(m_window, windowSizeX, windowSizeY);
            PCSX::g_emulator->m_spu->setCfg(j);
            PCSX::g_emulator->m_pads->setCfg(j);
        } else {
            PCSX::g_emulator->m_pads->setDefaults();
            saveCfg();
        }

        setFullscreen(m_fullscreen);
        const auto currentTheme =
            g_emulator->settings.get<Emulator::SettingGUITheme>().value;  // On boot: reload GUI theme
        applyTheme(currentTheme);

        if (emuSettings.get<Emulator::SettingMcd1>().empty()) {
            emuSettings.get<Emulator::SettingMcd1>() = MAKEU8(u8"memcard1.mcd");
        }

        if (emuSettings.get<Emulator::SettingMcd2>().empty()) {
            emuSettings.get<Emulator::SettingMcd2>() = MAKEU8(u8"memcard2.mcd");
        }

        PCSX::g_emulator->m_gpu->setDither(emuSettings.get<Emulator::SettingDither>());

        auto argPath1 = m_args.get<std::string>("memcard1");
        auto argPath2 = m_args.get<std::string>("memcard2");
        if (argPath1.has_value()) emuSettings.get<Emulator::SettingMcd1>().value = argPath1.value();
        if (argPath2.has_value()) emuSettings.get<Emulator::SettingMcd2>().value = argPath1.value();
        PCSX::u8string path1 = emuSettings.get<Emulator::SettingMcd1>().string();
        PCSX::u8string path2 = emuSettings.get<Emulator::SettingMcd2>().string();

        PCSX::g_emulator->m_sio->LoadMcds(path1, path2);
        auto biosCfg = m_args.get<std::string>("bios");
        if (biosCfg.has_value()) emuSettings.get<Emulator::SettingBios>() = biosCfg.value();

        g_system->activateLocale(emuSettings.get<PCSX::Emulator::SettingLocale>());

        g_system->m_eventBus->signal(Events::SettingsLoaded{});

        std::filesystem::path isoToOpen = m_args.get<std::string>("iso", "");
        if (!isoToOpen.empty()) PCSX::g_emulator->m_cdrom->m_iso.setIsoPath(isoToOpen);
        isoToOpen = m_args.get<std::string>("loadiso", "");
        if (!isoToOpen.empty()) PCSX::g_emulator->m_cdrom->m_iso.setIsoPath(isoToOpen);

        auto argPCdrv = m_args.get<bool>("pcdrv");
        auto argPCdrvBase = m_args.get<std::string>("pcdrvbase");
        if (argPCdrv.has_value()) {
            debugSettings.get<Emulator::DebugSettings::PCdrv>().value = argPCdrv.value();
        }
        if (argPCdrvBase.has_value()) {
            debugSettings.get<Emulator::DebugSettings::PCdrvBase>().value = argPCdrvBase.value();
        }
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
    m_createWindowOldCallback = platform_io.Platform_CreateWindow;
    platform_io.Platform_CreateWindow = [](ImGuiViewport* viewport) {
        s_gui->m_createWindowOldCallback(viewport);
        // absolutely horrendous hack, but the only way we have to grab the
        // newly created GLFWwindow pointer...
        auto window = *reinterpret_cast<GLFWwindow**>(viewport->PlatformUserData);
        glfwSetKeyCallback(window, glfwKeyCallbackTrampoline);
    };
    glfwSetKeyCallback(m_window, glfwKeyCallbackTrampoline);
    glfwSetJoystickCallback([](int jid, int event) { PCSX::g_emulator->m_pads->scanGamepads(); });
    ImGui_ImplOpenGL3_Init(GL_SHADER_VERSION);
    glGenTextures(1, &m_VRAMTexture);
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5_A1, 1024, 512);
    checkGL();
    g_system->m_eventBus->signal(Events::CreatedVRAMTexture{m_VRAMTexture});

    // offscreen stuff
    glGenFramebuffers(1, &m_offscreenFrameBuffer);
    glGenTextures(2, m_offscreenTextures);
    glGenRenderbuffers(1, &m_offscreenDepthBuffer);
    checkGL();

    m_mainVRAMviewer.setMain();
    m_mainVRAMviewer.setTitle([]() { return _("Main VRAM Viewer"); });
    m_clutVRAMviewer.setTitle([]() { return _("CLUT VRAM selector"); });
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

    m_offscreenShaderEditor.compile();
    m_outputShaderEditor.compile();

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
    m_currentTexture = 1;
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
    uv_run(&g_emulator->m_loop, UV_RUN_NOWAIT);
    if (glfwWindowShouldClose(m_window)) g_system->quit();
    glfwPollEvents();

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
    checkGL();

    // Check hotkeys (TODO: Make configurable)
    if (ImGui::IsKeyPressed(GLFW_KEY_ESCAPE)) m_showMenu = !m_showMenu;
    if (io.KeyAlt && ImGui::IsKeyPressed(GLFW_KEY_ENTER)) setFullscreen(!m_fullscreen);

    if (ImGui::IsKeyPressed(GLFW_KEY_F1)) {  // Save to quick-save slot
        zstr::ofstream save(buildSaveStateFilename(0), std::ios::binary);
        save << SaveStates::save();
    }

    if (ImGui::IsKeyPressed(GLFW_KEY_F2)) {  // Load from quick-save slot
        const auto saveStateName = buildSaveStateFilename(0);
        loadSaveState(saveStateName);
    }

    if (!g_system->running()) {
        if (ImGui::IsKeyPressed(GLFW_KEY_F10)) {
            g_emulator->m_debug->stepOver();
        } else if (ImGui::IsKeyPressed(GLFW_KEY_F11)) {
            if (ImGui::GetIO().KeyShift) {
                g_emulator->m_debug->stepOut();
            } else {
                g_emulator->m_debug->stepIn();
            }
        } else if (ImGui::IsKeyPressed(GLFW_KEY_F5)) {
            g_system->resume();
        }
    } else {
        if (ImGui::IsKeyPressed(GLFW_KEY_PAUSE) || ImGui::IsKeyPressed(GLFW_KEY_F6)) g_system->pause();
    }
    if (ImGui::IsKeyPressed(GLFW_KEY_F8)) {
        if (ImGui::GetIO().KeyShift) {
            g_system->hardReset();
        } else {
            g_system->softReset();
        }
    }
}

void PCSX::GUI::setViewport() { glViewport(0, 0, m_renderSize.x, m_renderSize.y); }

void PCSX::GUI::flip() {
    checkGL();

    glBindFramebuffer(GL_FRAMEBUFFER, m_offscreenFrameBuffer);
    checkGL();
    glBindTexture(GL_TEXTURE_2D, m_offscreenTextures[m_currentTexture]);
    checkGL();

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_renderSize.x, m_renderSize.y, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    checkGL();

    glBindRenderbuffer(GL_RENDERBUFFER, m_offscreenDepthBuffer);
    checkGL();
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH_COMPONENT24, m_renderSize.x, m_renderSize.y);
    checkGL();
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER, m_offscreenDepthBuffer);
    checkGL();
    GLuint texture = m_offscreenTextures[m_currentTexture];
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    checkGL();
    GLenum DrawBuffers[1] = {GL_COLOR_ATTACHMENT0};

    glDrawBuffers(1, DrawBuffers);  // "1" is the size of DrawBuffers
    // this check seems to sometime fails when the window is minimized...?
    checkGL();

    assert(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);

    glViewport(0, 0, m_renderSize.x, m_renderSize.y);

    glClearColor(0, 0, 0, 0);
    glClearDepthf(0.f);

    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    glFrontFace(GL_CW);
    glCullFace(GL_BACK);
    glEnable(GL_CULL_FACE);
    checkGL();

    glDisable(GL_CULL_FACE);
    m_currentTexture = m_currentTexture ? 0 : 1;
    checkGL();
}

void PCSX::GUI::endFrame() {
    auto& io = ImGui::GetIO();
    // bind back the output frame buffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    checkGL();
    auto& emuSettings = PCSX::g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();

    int w, h;
    glfwGetFramebufferSize(m_window, &w, &h);
    m_renderSize = ImVec2(w, h);
    normalizeDimensions(m_renderSize, m_renderRatio);

    bool changed = false;

    m_offscreenShaderEditor.configure();
    m_outputShaderEditor.configure();

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
        m_outputShaderEditor.renderWithImgui(texture, m_renderSize, logicalRenderSize);
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
            normalizeDimensions(textureSize, m_renderRatio);
            ImTextureID texture = reinterpret_cast<ImTextureID*>(m_offscreenTextures[m_currentTexture]);
            m_outputShaderEditor.renderWithImgui(texture, m_renderSize, textureSize);
        }
        ImGui::End();
        if (!outputShown) m_fullscreenRender = true;
    }

    bool showOpenIsoFileDialog = false;
    bool showOpenBinaryDialog = false;

    if (m_showMenu || !m_fullscreenRender || !PCSX::g_system->running()) {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu(_("File"))) {
                showOpenIsoFileDialog = ImGui::MenuItem(_("Open ISO"));
                if (ImGui::MenuItem(_("Close ISO"))) {
                    PCSX::g_emulator->m_cdrom->m_iso.close();
                    CheckCdrom();
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
                        zstr::ofstream save(buildSaveStateFilename(0), std::ios::binary);
                        save << SaveStates::save();
                    }

                    for (auto i = 1; i < 10; i++) {
                        const auto str = fmt::format(_("Slot {}"), i);
                        if (ImGui::MenuItem(str.c_str())) {
                            zstr::ofstream save(buildSaveStateFilename(i), std::ios::binary);
                            save << SaveStates::save();
                        }
                    }

                    ImGui::EndMenu();
                }

                if (ImGui::BeginMenu(_("Load state slots"))) {
                    if (ImGui::MenuItem(_("Quick-save slot"), "F2")) loadSaveState(buildSaveStateFilename(0));

                    for (auto i = 1; i < 10; i++) {
                        const auto str = fmt::format(_("Slot {}"), i);
                        if (ImGui::MenuItem(str.c_str())) loadSaveState(buildSaveStateFilename(i));
                    }

                    ImGui::EndMenu();
                }

                static constexpr char globalSaveState[] = "global.sstate";

                if (ImGui::MenuItem(_("Save global state"))) {
                    zstr::ofstream save(globalSaveState, std::ios::binary);
                    save << SaveStates::save();
                }

                if (ImGui::MenuItem(_("Load global state"))) loadSaveState(globalSaveState);

                ImGui::Separator();
                if (ImGui::MenuItem(_("Open LID"))) {
                    PCSX::g_emulator->m_cdrom->setCdOpenCaseTime(-1);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Close LID"))) {
                    PCSX::g_emulator->m_cdrom->setCdOpenCaseTime(0);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Open and close LID"))) {
                    PCSX::g_emulator->m_cdrom->setCdOpenCaseTime((int64_t)time(NULL) + 2);
                    PCSX::g_emulator->m_cdrom->lidInterrupt();
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Memory Card 1 inserted"), nullptr,
                                    &g_emulator->settings.get<Emulator::SettingMcd1Inserted>().value)) {
                    g_emulator->m_sio->interrupt();
                }
                if (ImGui::MenuItem(_("Memory Card 2 inserted"), nullptr,
                                    &g_emulator->settings.get<Emulator::SettingMcd2Inserted>().value)) {
                    g_emulator->m_sio->interrupt();
                }
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
                if (ImGui::MenuItem(_("Start"), "F5", nullptr, !g_system->running())) {
                    g_system->start();
                }
                if (ImGui::MenuItem(_("Pause"), "F6", nullptr, g_system->running())) {
                    g_system->pause();
                }
                if (ImGui::MenuItem(_("Soft Reset"), "F8")) {
                    g_system->softReset();
                }
                if (ImGui::MenuItem(_("Hard Reset"), "shift-F8")) {
                    g_system->hardReset();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Configuration"))) {
                if (ImGui::MenuItem(_("Emulation"), nullptr, &m_showCfg)) {
                    auto& overlays = g_emulator->settings.get<Emulator::SettingBiosOverlay>();
                    m_overlayFileOffsets.resize(overlays.size());
                    m_overlayLoadOffsets.resize(overlays.size());
                    m_overlayLoadSizes.resize(overlays.size());
                    unsigned counter = 0;
                    for (auto& overlay : overlays) {
                        char str[32];
                        std::snprintf(str, 32, "0x%08x", overlay.get<Emulator::OverlaySetting::FileOffset>().value);
                        m_overlayFileOffsets[counter] = str;
                        std::snprintf(str, 32, "0x%08x", overlay.get<Emulator::OverlaySetting::LoadOffset>().value);
                        m_overlayLoadOffsets[counter] = str;
                        std::snprintf(str, 32, "0x%08x", overlay.get<Emulator::OverlaySetting::LoadSize>().value);
                        m_overlayLoadSizes[counter] = str;
                        counter++;
                    }
                }
                ImGui::MenuItem(_("GPU"), nullptr, &PCSX::g_emulator->m_gpu->m_showCfg);
                ImGui::MenuItem(_("SPU"), nullptr, &PCSX::g_emulator->m_spu->m_showCfg);
                ImGui::MenuItem(_("UI"), nullptr, &m_showUiCfg);
                ImGui::MenuItem(_("Controls"), nullptr, &g_emulator->m_pads->m_showCfg);
                if (ImGui::BeginMenu(_("Shader presets"))) {
                    if (ImGui::MenuItem(_("Default shader"))) {
                        m_offscreenShaderEditor.setDefaults();
                        m_offscreenShaderEditor.compile();
                        m_offscreenShaderEditor.reset();
                        m_outputShaderEditor.setDefaults();
                        m_outputShaderEditor.compile();
                        m_outputShaderEditor.reset();
                    }
                    if (ImGui::MenuItem(_("CRT-lottes shader"))) {
                        m_offscreenShaderEditor.setText(Shaders::CrtLottes::Offscreen::vert(),
                                                        Shaders::CrtLottes::Offscreen::frag(),
                                                        Shaders::CrtLottes::Offscreen::lua());
                        m_offscreenShaderEditor.compile();
                        m_offscreenShaderEditor.reset();
                        m_outputShaderEditor.setText(Shaders::CrtLottes::Output::vert(),
                                                     Shaders::CrtLottes::Output::frag(),
                                                     Shaders::CrtLottes::Output::lua());
                        m_outputShaderEditor.compile();
                        m_outputShaderEditor.reset();
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
                    ImGui::EndMenu();
                }
                ImGui::MenuItem(_("Show Interrupts Scaler"), nullptr, &m_showInterruptsScaler);
                ImGui::MenuItem(_("Kernel Events"), nullptr, &m_events.m_show);
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
                if (ImGui::MenuItem(_("Start GPU dump"))) {
                    PCSX::g_emulator->m_gpu->startDump();
                }
                if (ImGui::MenuItem(_("Stop GPU dump"))) {
                    PCSX::g_emulator->m_gpu->stopDump();
                }
                ImGui::Separator();
                ImGui::MenuItem(_("Show types"), nullptr, &m_types.m_show);
                ImGui::MenuItem(_("Show source"), nullptr, &m_source.m_show);
                ImGui::Separator();
                ImGui::MenuItem(_("Fullscreen render"), nullptr, &m_fullscreenRender);
                ImGui::MenuItem(_("Show Output Shader Editor"), nullptr, &m_outputShaderEditor.m_show);
                ImGui::MenuItem(_("Show Offscreen Shader Editor"), nullptr, &m_offscreenShaderEditor.m_show);
                ImGui::Separator();
                ImGui::MenuItem(_("Show raw DWARF info"), nullptr, &m_dwarf.m_show);
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Help"))) {
                ImGui::MenuItem(_("Show ImGui Demo"), nullptr, &m_showDemo);
                ImGui::Separator();
                ImGui::MenuItem(_("About"), nullptr, &m_showAbout);
                ImGui::EndMenu();
            }
            ImGui::Separator();
            ImGui::Separator();
            ImGui::Text(_("CPU: %s"), g_emulator->m_psxCpu->isDynarec() ? "DynaRec" : "Interpreted");
            ImGui::Separator();
            ImGui::Text(_("GAME ID: %s"), g_emulator->m_cdromId);
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
            PCSX::g_emulator->m_cdrom->m_iso.close();
            PCSX::g_emulator->m_cdrom->m_iso.setIsoPath(reinterpret_cast<const char*>(fileToOpen[0].c_str()));
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
    m_mainVRAMviewer.draw(m_VRAMTexture, this);
    m_clutVRAMviewer.draw(m_VRAMTexture, this);
    for (auto& viewer : m_VRAMviewers) viewer.draw(m_VRAMTexture, this);

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
        m_luaInspector.draw(_("Lua Inspector"), g_emulator->m_lua.get(), this);
    }
    if (m_luaEditor.m_show) {
        m_luaEditor.draw(_("Lua Editor"), this);
    }
    if (m_events.m_show) {
        m_events.draw(reinterpret_cast<const uint32_t*>(g_emulator->m_psxMem->g_psxM), _("Kernel events"));
    }
    if (m_kernelLog.m_show) {
        changed |= m_kernelLog.draw(g_emulator->m_psxCpu.get(), _("Kernel Calls"));
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
                editor.draw(PCSX::g_emulator->m_psxMem->g_psxM, 8 * 1024 * 1024, 0x80000000);
            }
            counter++;
        }
        if (m_parallelPortEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_parallelPortEditor.draw(PCSX::g_emulator->m_psxMem->g_psxP, 64 * 1024, 0x1f000000);
        }
        counter++;
        if (m_scratchPadEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_scratchPadEditor.draw(PCSX::g_emulator->m_psxMem->g_psxH, 1024, 0x1f800000);
        }
        counter++;
        if (m_hwrEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_hwrEditor.draw(PCSX::g_emulator->m_psxMem->g_psxH + 4 * 1024, 8 * 1024, 0x1f801000);
        }
        counter++;
        if (m_biosEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_biosEditor.draw(PCSX::g_emulator->m_psxMem->g_psxR, 512 * 1024, 0xbfc00000);
        }
    }

    if (m_registers.m_show) {
        m_registers.draw(this, &PCSX::g_emulator->m_psxCpu->m_psxRegs, _("Registers"));
    }

    if (m_assembly.m_show) {
        m_assembly.draw(this, &PCSX::g_emulator->m_psxCpu->m_psxRegs, PCSX::g_emulator->m_psxMem.get(), &m_dwarf,
                        _("Assembly"));
    }

    if (m_breakpoints.m_show) {
        m_breakpoints.draw(_("Breakpoints"));
    }

    about();
    interruptsScaler();

    if (m_dwarf.m_show) {
        m_dwarf.draw(_("Dwarf"));
    }

    m_types.draw();
    if (m_source.m_show) {
        m_source.draw(_("Source"), g_emulator->m_psxCpu->m_psxRegs.pc, this);
    }

    if (m_outputShaderEditor.draw(_("Output Video"), this)) {
        // maybe throttle this?
        m_outputShaderEditor.compile();
    }

    if (m_offscreenShaderEditor.draw(_("Offscreen Render"), this)) {
        // maybe throttle this?
        m_offscreenShaderEditor.compile();
    }

    PCSX::g_emulator->m_spu->debug();
    changed |= PCSX::g_emulator->m_spu->configure();
    changed |= PCSX::g_emulator->m_gpu->configure();
    changed |= PCSX::g_emulator->m_pads->configure();
    changed |= configure();

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
            changed |= needFontReload;
            if (needFontReload) m_reloadFonts = true;
        }
        ImGui::End();
    }

    auto& L = g_emulator->m_lua;
    L->getfield("DrawImguiFrame", LUA_GLOBALSINDEX);
    if (!L->isnil()) {
        try {
            L->pcall();
            bool gotGLerror = false;
            GLenum glError = GL_NO_ERROR;
            while ((glError = glGetError()) != GL_NO_ERROR) {
                std::string msg = "glError: ";
                msg += glErrorToString(glError);
                m_luaConsole.addError(msg);
                if (m_args.get<bool>("lua_stdout", false)) {
                    fprintf(stderr, "%s\n", msg.c_str());
                }
                gotGLerror = true;
            }
            if (gotGLerror) throw("OpenGL error while running Lua code");
        } catch (...) {
            L->push();
            L->setfield("DrawImguiFrame", LUA_GLOBALSINDEX);
        }
    } else {
        L->pop();
    }
    m_notifier.draw();

    ImGui::Render();
    glViewport(0, 0, w, h);
    checkGL();
    if (m_fullscreenRender) {
        glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
    } else {
        glClearColor(m_backgroundColor.x, m_backgroundColor.y, m_backgroundColor.z, m_backgroundColor.w);
    }
    checkGL();
    glClearDepthf(0.0f);
    checkGL();
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    checkGL();

    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        GLFWwindow* backup_current_context = glfwGetCurrentContext();
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        glfwMakeContextCurrent(backup_current_context);
    }

    glfwSwapBuffers(m_window);
    checkGL();
    glFlush();
    checkGL();

    if (changed) saveCfg();
    if (m_gotImguiUserError) {
        g_system->log(LogClass::UI, "Got ImGui User Error: %s\n", m_imguiUserError.c_str());
        m_gotImguiUserError = false;
        L->push();
        L->setfield("DrawImguiFrame", LUA_GLOBALSINDEX);
    }

    FrameMark
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

bool PCSX::GUI::configure() {
    bool changed = false;
    bool selectBiosDialog = false;
    bool selectBiosOverlayDialog = false;
    auto& settings = g_emulator->settings;
    auto& debugSettings = settings.get<Emulator::SettingDebugSettings>();
    if (!m_showCfg) return false;

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
        changed |= ImGui::SliderFloat(_("Speed Scaler"), &scale, 0.1f, 10.0f);
        settings.get<Emulator::SettingScaler>() = scale * 100.0f;
        changed |= ImGui::Checkbox(_("Enable XA decoder"), &settings.get<Emulator::SettingXa>().value);
        changed |= ImGui::Checkbox(_("Always enable SPU IRQ"), &settings.get<Emulator::SettingSpuIrq>().value);
        changed |= ImGui::Checkbox(_("Decode MDEC videos in B&W"), &settings.get<Emulator::SettingBnWMdec>().value);
        changed |= ImGui::Checkbox(_("Dynarec CPU"), &settings.get<Emulator::SettingDynarec>().value);
        ShowHelpMarker(_(R"(Activates the dynamic-recompiler CPU core.
It is significantly faster than the interpreted CPU,
however it doesn't play nicely with the debugger.
Changing this setting requires a reboot to take effect.
The dynarec core isn't available for all CPUs, so
this setting may not have any effect for you.)"));
        changed |= ImGui::Checkbox(_("8MB"), &settings.get<Emulator::Setting8MB>().value);
        ShowHelpMarker(_(R"(Emulates an installed 8MB system,
instead of the normal 2MB. Useful for working
with development binaries and games.)"));

        {
            static const char* types[] = {"Auto", "NTSC", "PAL"};
            auto& autodetect = settings.get<Emulator::SettingAutoVideo>().value;
            auto& type = settings.get<Emulator::SettingVideo>().value;
            if (ImGui::BeginCombo(_("System Type"), types[autodetect ? 0 : (type + 1)])) {
                if (ImGui::Selectable(types[0], autodetect)) {
                    changed = true;
                    autodetect = true;
                }
                if (ImGui::Selectable(types[1], !autodetect && (type == PCSX::Emulator::PSX_TYPE_NTSC))) {
                    changed = true;
                    type = PCSX::Emulator::PSX_TYPE_NTSC;
                    autodetect = false;
                }
                if (ImGui::Selectable(types[2], !autodetect && (type == PCSX::Emulator::PSX_TYPE_PAL))) {
                    changed = true;
                    type = PCSX::Emulator::PSX_TYPE_PAL;
                    autodetect = false;
                }
                ImGui::EndCombo();
            }
        }

        {
            const char* labels[] = {_("Disabled"), _("Little Endian"), _("Big Endian")};
            auto& cdda = settings.get<Emulator::SettingCDDA>().value;
            if (ImGui::BeginCombo(_("CDDA"), labels[cdda])) {
                int counter = 0;
                for (auto& label : labels) {
                    if (ImGui::Selectable(label, cdda == counter)) {
                        changed = true;
                        cdda = decltype(cdda)(counter);
                    }
                    counter++;
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
        changed |= ImGui::Checkbox(_("Enable Debugger"), &debugSettings.get<Emulator::DebugSettings::Debug>().value);
        ShowHelpMarker(_(R"(This will enable the usage of various breakpoints
throughout the execution of mips code. Enabling this
can slow down emulation to a noticable extend.)"));
        if (ImGui::Checkbox(_("Enable GDB Server"), &debugSettings.get<Emulator::DebugSettings::GdbServer>().value)) {
            changed = true;
            if (debugSettings.get<Emulator::DebugSettings::GdbServer>()) {
                g_emulator->m_gdbServer->startServer(&g_emulator->m_loop,
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
                g_emulator->m_webServer->startServer(&g_emulator->m_loop,
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
        if (ImGui::CollapsingHeader(_("Advanced BIOS patching"))) {
            auto& overlays = settings.get<Emulator::SettingBiosOverlay>();
            if (ImGui::Button(_("Add one entry"))) overlays.push_back({});
            m_overlayFileOffsets.resize(overlays.size());
            m_overlayLoadOffsets.resize(overlays.size());
            m_overlayLoadSizes.resize(overlays.size());
            int counter = 0;
            int overlayToRemove = -1;
            int swapMe = -1;
            for (auto& overlay : overlays) {
                std::string id = "overlay" + std::to_string(counter);
                ImGui::BeginChild(id.c_str(), ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 7.0f), true);
                auto overlayFilename = overlay.get<Emulator::OverlaySetting::Filename>().string();
                ImGui::InputText(_("Filename"),
                                 const_cast<char*>(reinterpret_cast<const char*>(overlayFilename.c_str())),
                                 overlayFilename.length(), ImGuiInputTextFlags_ReadOnly);
                ImGui::SameLine();
                if (ImGui::Button("...")) {
                    selectBiosOverlayDialog = true;
                    m_selectedBiosOverlayId = counter;
                }
                if (ImGui::InputText(_("File Offset"), &m_overlayFileOffsets[counter])) {
                    char* endPtr;
                    uint32_t offset = strtoul(m_overlayFileOffsets[counter].c_str(), &endPtr, 0);
                    if (!m_overlayFileOffsets[counter].empty() && !*endPtr) {
                        overlay.get<Emulator::OverlaySetting::FileOffset>().value = offset;
                        changed = true;
                    }
                }
                if (ImGui::InputText(_("Load Offset"), &m_overlayLoadOffsets[counter])) {
                    char* endPtr;
                    uint32_t offset = strtoul(m_overlayLoadOffsets[counter].c_str(), &endPtr, 0);
                    if (!m_overlayLoadOffsets[counter].empty() && !*endPtr) {
                        overlay.get<Emulator::OverlaySetting::LoadOffset>().value = offset;
                        changed = true;
                    }
                }
                if (ImGui::InputText(_("Load Size"), &m_overlayLoadSizes[counter])) {
                    char* endPtr;
                    uint32_t size = strtoul(m_overlayLoadSizes[counter].c_str(), &endPtr, 0);
                    if (!m_overlayLoadSizes[counter].empty() && !*endPtr) {
                        overlay.get<Emulator::OverlaySetting::LoadSize>().value = size;
                        changed = true;
                    }
                }
                if (ImGui::Checkbox(_("Enabled"), &overlay.get<Emulator::OverlaySetting::Enabled>().value))
                    changed = true;
                ImGui::SameLine();
                if (ImGui::Button(_("Remove"))) {
                    overlayToRemove = counter;
                }
                ImGui::SameLine();
                if (ImGui::Button(_("Move up"))) {
                    swapMe = counter - 1;
                }
                ImGui::SameLine();
                if (ImGui::Button(_("Move down"))) {
                    swapMe = counter;
                }
                ImGui::EndChild();
                counter++;
            }
            if (overlayToRemove >= 0) {
                overlays.erase(overlays.begin() + overlayToRemove);
                changed = true;
            }
            if ((swapMe >= 0) && (swapMe != (overlays.size() - 1))) {
                std::iter_swap(overlays.begin() + swapMe, overlays.begin() + swapMe + 1);
                std::iter_swap(m_overlayFileOffsets.begin() + swapMe, m_overlayFileOffsets.begin() + swapMe + 1);
                std::iter_swap(m_overlayLoadOffsets.begin() + swapMe, m_overlayLoadOffsets.begin() + swapMe + 1);
                std::iter_swap(m_overlayLoadSizes.begin() + swapMe, m_overlayLoadSizes.begin() + swapMe + 1);
                changed = true;
            }
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

    if (selectBiosOverlayDialog) m_selectBiosOverlayDialog.openDialog();
    if (m_selectBiosOverlayDialog.draw()) {
        std::vector<PCSX::u8string> fileToOpen = m_selectBiosOverlayDialog.selected();
        if (!fileToOpen.empty()) {
            settings.get<Emulator::SettingBiosOverlay>()[m_selectedBiosOverlayId]
                .get<Emulator::OverlaySetting::Filename>()
                .value = fileToOpen[0];
            changed = true;
        }
    }
    return changed;
}

void PCSX::GUI::interruptsScaler() {
    if (!m_showInterruptsScaler) return;
    static const char* names[] = {
        "SIO",         "CDR",         "CDR Read", "GPU DMA", "MDEC Out DMA",       "SPU DMA",      "GPU Busy",
        "MDEC In DMA", "GPU OTC DMA", "CDR DMA",  "SPU",     "CDR Decoded Buffer", "CDR Lid Seek", "CDR Play"};
    if (ImGui::Begin(_("Interrupt Scaler"), &m_showInterruptsScaler)) {
        if (ImGui::Button(_("Reset all"))) {
            for (auto& scale : g_emulator->m_psxCpu->m_interruptScales) {
                scale = 1.0f;
            }
        }
        unsigned counter = 0;
        for (auto& scale : g_emulator->m_psxCpu->m_interruptScales) {
            ImGui::SliderFloat(names[counter], &scale, 0.0f, 100.0f, "%.3f", ImGuiSliderFlags_AlwaysClamp);
            counter++;
        }
    }
    ImGui::End();
}

bool PCSX::GUI::showThemes() {
    static const char* imgui_themes[] = {"Default", "Classic", "Light", "Cherry",
                                         "Mono",    "Dracula", "Olive"};  // Used for theme combo box
    auto changed = false;
    auto& currentTheme = g_emulator->settings.get<Emulator::SettingGUITheme>().value;

    if (ImGui::BeginCombo(_("Themes"), imgui_themes[currentTheme], ImGuiComboFlags_HeightLarge)) {
        for (int n = 0; n < IM_ARRAYSIZE(imgui_themes); n++) {
            bool selected = (currentTheme == n);
            if (ImGui::Selectable(imgui_themes[n], selected)) {
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

void PCSX::GUI::about() {
    if (!m_showAbout) return;
    ImGui::SetNextWindowPos(ImVec2(200, 100), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(880, 600), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(_("About"), &m_showAbout)) {
        ImGui::Text("PCSX-Redux");
        ImGui::Separator();
        auto someString = [](const char* str, GLenum index) {
            const char* value = (const char*)glGetString(index);
            checkGL();
            ImGui::TextWrapped("%s: %s", str, value);
        };
        if (ImGui::BeginTabBar("AboutTabs", ImGuiTabBarFlags_None)) {
            if (ImGui::BeginTabItem(_("Authors"))) {
                ImGui::BeginChild("Authors", ImVec2(0, 0), true);
                ImGui::Text("%s",
#include "AUTHORS"
                );
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("OpenGL information"))) {
                ImGui::Text(_("Core profile: %s"), m_hasCoreProfile ? "yes" : "no");
                someString(_("Vendor"), GL_VENDOR);
                someString(_("Renderer"), GL_RENDERER);
                someString(_("Version"), GL_VERSION);
                someString(_("Shading language version"), GL_SHADING_LANGUAGE_VERSION);
                GLint n, i;
                glGetIntegerv(GL_NUM_EXTENSIONS, &n);
                checkGL();
                ImGui::TextUnformatted(_("Extensions:"));
                ImGui::BeginChild("GLextensions", ImVec2(0, 0), true);
                for (i = 0; i < n; i++) {
                    const char* extension = (const char*)glGetStringi(GL_EXTENSIONS, i);
                    checkGL();
                    ImGui::Text("%s", extension);
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void PCSX::GUI::update(bool vsync) {
    endFrame();
    startFrame();
    if (vsync && m_breakOnVSync) g_system->pause();
}

void PCSX::GUI::shellReached() {
    auto& regs = g_emulator->m_psxCpu->m_psxRegs;
    uint32_t oldPC = regs.pc;
    if (g_emulator->settings.get<PCSX::Emulator::SettingFastBoot>()) regs.pc = regs.GPR.n.ra;

    if (m_exeToLoad.empty()) return;
    PCSX::u8string filename = m_exeToLoad.get();
    std::filesystem::path p = filename;

    g_system->log(LogClass::UI, "Hijacked shell, loading %s...\n", p.string());
    bool success = BinaryLoader::load(filename);
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
        PCSX::g_emulator->m_cdrom->m_iso.setIsoPath(pathStr);
    }

    free(extension);
}

std::string PCSX::GUI::buildSaveStateFilename(int i) {
    // the ID of the game. Every savestate is marked with the ID of the game it's from.
    const auto gameID = g_emulator->m_cdromId;

    // Check if the game has a non-NULL ID or a game hasn't been loaded. Some stuff like PS-X
    // EXEs don't have proper IDs
    if (gameID[0] != 0) {
        // For games with an ID of SLUS00213 for example, this will generate a state named
        // SLUS00213.sstate
        return fmt::format("{}.sstate{}", gameID, i);
    } else {
        // For games without IDs, identify them via filename
        const auto& iso = PCSX::g_emulator->m_cdrom->m_iso.getIsoPath().filename();
        const auto lastFile = iso.empty() ? "BIOS" : iso.string();
        return fmt::format("{}.sstate{}", lastFile, i);
    }
}

void PCSX::GUI::loadSaveState(const std::filesystem::path& filename) {
    if (!std::filesystem::exists(std::filesystem::path(filename))) return;  // Return if the savestate doesn't exist

    zstr::ifstream save(filename.string(), std::ios::binary);
    std::ostringstream os;
    constexpr unsigned buff_size = 1 << 16;
    char* buff = new char[buff_size];

    while (true) {
        save.read(buff, buff_size);
        std::streamsize cnt = save.gcount();
        if (cnt == 0) break;
        os.write(buff, cnt);
    }

    delete[] buff;
    SaveStates::load(os.str());
};
