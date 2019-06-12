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

#include <SDL.h>
#include <assert.h>

#include <fstream>
#include <iomanip>
#include <unordered_set>

#include "flags.h"
#include "json.hpp"

#include "GL/gl3w.h"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_sdl.h"

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "gui/gui.h"
#include "spu/interface.h"

using json = nlohmann::json;

void PCSX::GUI::bindVRAMTexture() {
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    checkGL();
}

void PCSX::GUI::checkGL() {
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        SDL_TriggerBreakpoint();
        abort();
    }
}

void PCSX::GUI::setFullscreen(bool fullscreen) {
    m_fullscreen = fullscreen;
    if (fullscreen) {
        SDL_SetWindowFullscreen(m_window, SDL_WINDOW_FULLSCREEN_DESKTOP);
    } else {
        SDL_SetWindowFullscreen(m_window, 0);
    }
}

void PCSX::GUI::init() {
    // SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_DEBUG_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
    Uint32 flags = SDL_WINDOW_OPENGL | SDL_WINDOW_ALLOW_HIGHDPI | SDL_WINDOW_RESIZABLE;
    if (m_args.get<bool>("fullscreen", false)) flags |= SDL_WINDOW_FULLSCREEN_DESKTOP;

    m_window = SDL_CreateWindow("PCSX-Redux", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 800, flags);
    assert(m_window);

    m_glContext = SDL_GL_CreateContext(m_window);
    assert(m_glContext);

    int result = gl3wInit();
    assert(result == 0);

    SDL_GL_SetSwapInterval(0);

    // Setup ImGui binding
    ImGui::CreateContext();
    {
        ImGui::GetIO().IniFilename = nullptr;
        std::ifstream cfg("pcsx.json");
        auto& emuSettings = PCSX::g_emulator.settings;
        json j;
        if (cfg.is_open()) {
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
            SDL_SetWindowPosition(m_window, settings.get<WindowPosX>(), settings.get<WindowPosY>());
            SDL_SetWindowSize(m_window, settings.get<WindowSizeX>(), settings.get<WindowSizeY>());
            PCSX::g_emulator.m_spu->setCfg(j);
        } else {
            saveCfg();
        }

        setFullscreen(m_fullscreen);

        if (emuSettings.get<Emulator::SettingMcd1>().empty()) {
            emuSettings.get<Emulator::SettingMcd1>() = "memcard1.mcd";
        }

        if (emuSettings.get<Emulator::SettingMcd2>().empty()) {
            emuSettings.get<Emulator::SettingMcd2>() = "memcard2.mcd";
        }

        std::string path1 = emuSettings.get<Emulator::SettingMcd1>().string();
        std::string path2 = emuSettings.get<Emulator::SettingMcd2>().string();
        PCSX::g_emulator.m_sio->LoadMcds(path1.c_str(), path2.c_str());
    }
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_ViewportsEnable | ImGuiConfigFlags_DockingEnable;
    ImGui_ImplOpenGL3_Init("#version 300 es");
    ImGui_ImplSDL2_InitForOpenGL(m_window, m_glContext);

    glGenTextures(1, &m_VRAMTexture);
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5_A1, 1024, 512);
    checkGL();

    // offscreen stuff
    glGenFramebuffers(1, &m_offscreenFrameBuffer);
    glGenTextures(2, m_offscreenTextures);
    glGenRenderbuffers(1, &m_offscreenDepthBuffer);
    checkGL();

    m_mainVRAMviewer.init();
    m_mainVRAMviewer.setTitle([]() { return _("Main VRAM Viewer"); });
    m_clutVRAMviewer.init();
    m_clutVRAMviewer.setTitle([]() { return _("CLUT VRAM selector"); });
    unsigned counter = 1;
    for (auto& viewer : m_VRAMviewers) {
        viewer.init();
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

    startFrame();
    m_currentTexture = 1;
    flip();
}

void PCSX::GUI::close() {
    SDL_DestroyWindow(m_window);
    SDL_Quit();
}

void PCSX::GUI::saveCfg() {
    std::ofstream cfg("pcsx.json");
    json j;

    SDL_GetWindowPosition(m_window, &settings.get<WindowPosX>().value, &settings.get<WindowPosY>().value);
    SDL_GetWindowSize(m_window, &settings.get<WindowSizeX>().value, &settings.get<WindowSizeY>().value);

    j["imgui"] = ImGui::SaveIniSettingsToMemory(nullptr);
    j["SPU"] = PCSX::g_emulator.m_spu->getCfg();
    j["emulator"] = PCSX::g_emulator.settings.serialize();
    j["gui"] = settings.serialize();
    cfg << std::setw(2) << j << std::endl;
}

void PCSX::GUI::startFrame() {
    SDL_Event event;
    std::unordered_set<SDL_Scancode> keyset;
    SDL_Keymod mods = SDL_GetModState();
    while (SDL_PollEvent(&event)) {
        bool passthrough = true;
        SDL_Scancode sc = event.key.keysym.scancode;
        switch (event.type) {
            case SDL_QUIT:
                PCSX::g_system->quit();
                break;
            case SDL_KEYDOWN:
                if ((mods & KMOD_ALT) && (sc == SDL_SCANCODE_RETURN)) {
                    setFullscreen(!m_fullscreen);
                    passthrough = false;
                } else {
                    keyset.insert(sc);
                }
                break;
            case SDL_WINDOWEVENT:
                switch (event.window.event) {
                    case SDL_WINDOWEVENT_MOVED:
                    case SDL_WINDOWEVENT_RESIZED:
                    case SDL_WINDOWEVENT_SIZE_CHANGED:
                        saveCfg();
                        break;
                }
                break;
        }
        if (passthrough) ImGui_ImplSDL2_ProcessEvent(&event);
    }
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(m_window);
    ImGui::NewFrame();
    if (ImGui::GetIO().WantSaveIniSettings) {
        ImGui::GetIO().WantSaveIniSettings = false;
        saveCfg();
    }
    SDL_GL_SwapWindow(m_window);
    glBindFramebuffer(GL_FRAMEBUFFER, m_offscreenFrameBuffer);
    checkGL();

    if (!ImGui::GetIO().WantCaptureKeyboard) {
        for (auto& scancode : keyset) {
            switch (scancode) {
                case SDL_SCANCODE_ESCAPE:
                    m_showMenu = !m_showMenu;
                    break;
            }
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
    checkGL();

    assert(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);

    glViewport(0, 0, m_renderSize.x, m_renderSize.y);

    glClearColor(0, 0, 0, 0);
    glClearDepthf(0.f);

    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    checkGL();

    glDisable(GL_CULL_FACE);
    m_currentTexture = m_currentTexture ? 0 : 1;
    checkGL();
}

void PCSX::GUI::endFrame() {
    // bind back the output frame buffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    checkGL();

    glViewport(0, 0, (int)ImGui::GetIO().DisplaySize.x, (int)ImGui::GetIO().DisplaySize.y);
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

    int w, h;
    SDL_GL_GetDrawableSize(m_window, &w, &h);
    m_renderSize = ImVec2(w, h);
    normalizeDimensions(m_renderSize, m_renderRatio);

    bool changed = false;

    if (m_fullscreenRender) {
        ImTextureID texture = ImTextureID(m_offscreenTextures[m_currentTexture]);
        auto basePos = ImGui::GetMainViewport()->Pos;
        ImGui::SetNextWindowPos(ImVec2((w - m_renderSize.x) / 2.0f + basePos.x, (h - m_renderSize.y) / 2.0f + basePos.y));
        ImGui::SetNextWindowSize(m_renderSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::Begin("FullScreenRender", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                         ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::Image(texture, m_renderSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::End();
        ImGui::PopStyleVar(2);
    }

    bool showOpenIsoFileDialog = false;

    if (m_showMenu || !m_fullscreenRender || !PCSX::g_system->running()) {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu(_("File"))) {
                showOpenIsoFileDialog = ImGui::MenuItem(_("Open ISO"));
                if (ImGui::MenuItem(_("Close ISO"))) {
                    PCSX::g_emulator.m_cdrom->m_iso.close();
                    CheckCdrom();
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Open LID"))) {
                    PCSX::g_emulator.m_cdrom->setCdOpenCaseTime(-1);
                    PCSX::g_emulator.m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Close LID"))) {
                    PCSX::g_emulator.m_cdrom->setCdOpenCaseTime(0);
                    PCSX::g_emulator.m_cdrom->lidInterrupt();
                }
                if (ImGui::MenuItem(_("Open and close LID"))) {
                    PCSX::g_emulator.m_cdrom->setCdOpenCaseTime((int64_t)time(NULL) + 2);
                    PCSX::g_emulator.m_cdrom->lidInterrupt();
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Quit"))) {
                    PCSX::g_system->quit();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Emulation"))) {
                if (ImGui::MenuItem(_("Start"), nullptr, nullptr, !PCSX::g_system->running())) {
                    PCSX::g_system->start();
                }
                if (ImGui::MenuItem(_("Pause"), nullptr, nullptr, PCSX::g_system->running())) {
                    PCSX::g_system->stop();
                }
                if (ImGui::MenuItem(_("Soft Reset"))) {
                    scheduleSoftReset();
                }
                if (ImGui::MenuItem(_("Hard Reset"))) {
                    scheduleHardReset();
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Configuration"))) {
                ImGui::MenuItem(_("Emulation"), nullptr, &m_showCfg);
                ImGui::MenuItem(_("GPU"), nullptr, &PCSX::g_emulator.m_gpu->m_showCfg);
                ImGui::MenuItem(_("SPU"), nullptr, &PCSX::g_emulator.m_spu->m_showCfg);
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu(_("Debug"))) {
                ImGui::MenuItem(_("Show Logs"), nullptr, &m_log.m_show);
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
                ImGui::MenuItem(_("Show BIOS counters"), nullptr, &m_showBiosCounters);
                ImGui::Separator();
                ImGui::MenuItem(_("Show SPU debug"), nullptr, &PCSX::g_emulator.m_spu->m_showDebug);
                ImGui::Separator();
                ImGui::MenuItem(_("Fullscreen render"), nullptr, &m_fullscreenRender);
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
            ImGui::Text(_("%.2f FPS (%.2f ms)"), ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);

            ImGui::EndMainMenuBar();
        }
    }

    auto& isoPath = g_emulator.settings.get<Emulator::SettingIsoPath>();

    if (showOpenIsoFileDialog) {
        if (!isoPath.empty()) {
            m_openIsoFileDialog.m_currentPath = isoPath.value;
        }
        m_openIsoFileDialog.openDialog();
    }
    if (m_openIsoFileDialog.draw()) {
        isoPath.value = m_openIsoFileDialog.m_currentPath;
        changed = true;
        std::vector<std::string> fileToOpen = m_openIsoFileDialog.selected();
        if (!fileToOpen.empty()) {
            PCSX::g_emulator.m_cdrom->m_iso.close();
            SetIsoFile(fileToOpen[0].c_str());
            PCSX::g_emulator.m_cdrom->m_iso.open();
            CheckCdrom();
        }
    }

    if (m_showDemo) ImGui::ShowDemoWindow();

    ImGui::SetNextWindowPos(ImVec2(10, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1024, 512), ImGuiCond_FirstUseEver);
    m_mainVRAMviewer.render(m_VRAMTexture);
    m_clutVRAMviewer.render(m_VRAMTexture);
    for (auto& viewer : m_VRAMviewers) viewer.render(m_VRAMTexture);

    if (!m_fullscreenRender) {
        ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(640, 480), ImGuiCond_FirstUseEver);
        bool outputShown = true;
        if (ImGui::Begin(
                _("Output"), &outputShown,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse)) {
            ImVec2 textureSize = ImGui::GetContentRegionAvail();
            normalizeDimensions(textureSize, m_renderRatio);
            ImGui::Image((ImTextureID)m_offscreenTextures[m_currentTexture], textureSize, ImVec2(0, 0), ImVec2(1, 1));
        }
        ImGui::End();
        if (!outputShown) m_fullscreenRender = true;
    }

    if (m_log.m_show) {
        ImGui::SetNextWindowPos(ImVec2(10, 540), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1200, 250), ImGuiCond_FirstUseEver);
        m_log.draw(_("Logs"));
    }

    {
        unsigned counter = 0;
        for (auto& editor : m_mainMemEditors) {
            if (editor.show) {
                ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
                ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
                editor.draw(PCSX::g_emulator.m_psxMem->g_psxM, 2 * 1024 * 1024, 0x80000000);
            }
            counter++;
        }
        if (m_parallelPortEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_parallelPortEditor.draw(PCSX::g_emulator.m_psxMem->g_psxP, 64 * 1024, 0x1f000000);
        }
        counter++;
        if (m_scratchPadEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_scratchPadEditor.draw(PCSX::g_emulator.m_psxMem->g_psxH, 1024, 0x1f800000);
        }
        counter++;
        if (m_hwrEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_hwrEditor.draw(PCSX::g_emulator.m_psxMem->g_psxH + 8 * 1024, 8 * 1024, 0x1f801000);
        }
        counter++;
        if (m_biosEditor.show) {
            ImGui::SetNextWindowPos(ImVec2(520, 30 + 10 * counter), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
            m_biosEditor.draw(PCSX::g_emulator.m_psxMem->g_psxR, 512 * 1024, 0xbfc00000);
        }
    }

    if (m_registers.m_show) {
        m_registers.draw(&PCSX::g_emulator.m_psxCpu->m_psxRegs, _("Registers"));
    }

    if (m_assembly.m_show) {
        m_assembly.draw(&PCSX::g_emulator.m_psxCpu->m_psxRegs, PCSX::g_emulator.m_psxMem.get(), _("Assembly"));
    }

    if (m_breakpoints.m_show) {
        m_breakpoints.draw(_("Breakpoints"));
    }

    about();
    biosCounters();

    PCSX::g_emulator.m_spu->debug();
    changed |= PCSX::g_emulator.m_spu->configure();
    changed |= PCSX::g_emulator.m_gpu->configure();
    changed |= configure();

    auto& io = ImGui::GetIO();

    ImGui::Render();
    glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    checkGL();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        SDL_Window* backup_current_window = SDL_GL_GetCurrentWindow();
        SDL_GLContext backup_current_context = SDL_GL_GetCurrentContext();
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        SDL_GL_MakeCurrent(backup_current_window, backup_current_context);
    }
    checkGL();
    glFlush();
    checkGL();

    if (changed) saveCfg();
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
    auto& settings = PCSX::g_emulator.settings;
    if (!m_showCfg) return false;

    ImGui::SetNextWindowPos(ImVec2(50, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 500), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(_("Emulation Configuration"), &m_showCfg)) {
        {
            std::string currentLocale = g_system->localeName();
            if (currentLocale.length() == 0) currentLocale = "English";
            if (ImGui::BeginCombo(_("Locale"), currentLocale.c_str())) {
                if (ImGui::Selectable("English", currentLocale == "English")) {
                    g_system->activateLocale("English");
                    g_emulator.settings.get<Emulator::SettingLocale>() = "English";
                    changed = true;
                }
                for (auto& l : g_system->localesNames()) {
                    if (ImGui::Selectable(l.c_str(), currentLocale == l)) {
                        g_system->activateLocale(l);
                        g_emulator.settings.get<Emulator::SettingLocale>() = l;
                        changed = true;
                    }
                }
                ImGui::EndCombo();
            }
            if (ImGui::Button(_("Reload locales"))) {
                g_system->loadAllLocales();
                g_system->activateLocale(currentLocale);
            }
        }
        ImGui::Separator();
        changed |= ImGui::Checkbox(_("Enable XA decoder"), &settings.get<Emulator::SettingXa>().value);
        changed |= ImGui::Checkbox(_("Always enable SIO IRQ"), &settings.get<Emulator::SettingSioIrq>().value);
        changed |= ImGui::Checkbox(_("Always enable SPU IRQ"), &settings.get<Emulator::SettingSpuIrq>().value);
        changed |= ImGui::Checkbox(_("Decode MDEC videos in B&W"), &settings.get<Emulator::SettingBnWMdec>().value);

        {
            static const char* types[] = {"Auto", "NTSC", "PAL"};
            auto& autodetect = settings.get<Emulator::SettingAutoVideo>().value;
            auto& type = settings.get<Emulator::SettingVideo>().value;
            if (ImGui::BeginCombo(_("System Type"), types[type])) {
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

        changed |= ImGui::Checkbox(_("BIOS HLE"), &settings.get<Emulator::SettingHLE>().value);
        changed |= ImGui::Checkbox(_("Fast boot"), &settings.get<Emulator::SettingFastBoot>().value);
        auto bios = settings.get<Emulator::SettingBios>().string();
        ImGui::InputText(_("BIOS file"), const_cast<char*>(bios.c_str()), bios.length(), ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        selectBiosDialog = ImGui::Button("...");
    }
    ImGui::End();

    if (selectBiosDialog) m_selectBiosDialog.openDialog();
    if (m_selectBiosDialog.draw()) {
        std::vector<std::string> fileToOpen = m_selectBiosDialog.selected();
        if (!fileToOpen.empty()) settings.get<Emulator::SettingBios>().value = fileToOpen[0];
    }
    return changed;
}

void PCSX::GUI::biosCounters() {
    if (!m_showBiosCounters) return;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(750, 530), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(_("BIOS Counters"), &m_showBiosCounters)) {
        auto isUnknown = [](const char* name, char syscall) {
            if (strlen(name) != 9) return false;
            if (strncmp(name, "sys_", 4) != 0) return false;
            if (name[4] != syscall) return false;
            if (name[5] != '0') return false;
            if (name[6] != '_') return false;
            return true;
        };
        if (ImGui::Button(_("Memorize"))) {
            g_emulator.m_psxCpu->memorizeCounters();
        }
        ImGui::SameLine();
        if (ImGui::Button(_("Clear"))) {
            g_emulator.m_psxCpu->clearCounters();
        }
        ImGui::SameLine();
        ImGui::Checkbox(_("Enable counters"), &g_emulator.m_psxCpu->m_biosCounters);
        ImGui::SameLine();
        ImGui::Checkbox(_("Skip unknowns"), &m_skipBiosUnknowns);
        ImGui::SameLine();
        ImGui::Checkbox(_("Debug kernel"), &g_emulator.m_psxCpu->m_debugKernel);
        ImGui::Checkbox(_("Log new syscalls"), &g_emulator.m_psxCpu->m_logNewSyscalls);
        ImGui::SameLine();
        ImGui::Checkbox(_("Log events"), &g_emulator.m_psxCpu->m_logEvents);
        ImGui::SameLine();
        ImGui::Checkbox(_("Breakpoint on new syscalls"), &g_emulator.m_psxCpu->m_breakpointOnNew);
        ImGui::Separator();
        ImGui::BeginChild("A0", ImVec2(ImGui::GetWindowContentRegionWidth() * 0.33f, 0));
        for (int i = 0; i < 256; i++) {
            char defaultName[16];
            const char* name = g_emulator.m_psxBios->getA0name(i);
            if (!name) {
                name = defaultName;
                std::snprintf(defaultName, 16, "sys_a0_%02x", i);
            }
            if (m_skipBiosUnknowns && isUnknown(name, 'a')) continue;
            char checkboxName[16];
            std::snprintf(checkboxName, 16, "##sys_a0_%02x_brk", i);
            ImGui::Text("%9u", g_emulator.m_psxCpu->getCounters(0)[i]);
            ImGui::SameLine();
            ImGui::Checkbox(checkboxName, &g_emulator.m_psxCpu->m_breakpoints[0][i]);
            ImGui::SameLine();
            ImGui::Text(name);
        }
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("B0", ImVec2(ImGui::GetWindowContentRegionWidth() * 0.33f, 0));
        for (int i = 0; i < 256; i++) {
            char defaultName[16];
            const char* name = g_emulator.m_psxBios->getB0name(i);
            if (!name) {
                name = defaultName;
                std::snprintf(defaultName, 16, "sys_b0_%02x", i);
            }
            if (m_skipBiosUnknowns && isUnknown(name, 'b')) continue;
            char checkboxName[16];
            std::snprintf(checkboxName, 16, "##sys_b0_%02x_brk", i);
            ImGui::Text("%9u", g_emulator.m_psxCpu->getCounters(1)[i]);
            ImGui::SameLine();
            ImGui::Checkbox(checkboxName, &g_emulator.m_psxCpu->m_breakpoints[1][i]);
            ImGui::SameLine();
            ImGui::Text(name);
        }
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("C0", ImVec2(ImGui::GetWindowContentRegionWidth() * 0.33f, 0));
        for (int i = 0; i < 256; i++) {
            char defaultName[16];
            const char* name = g_emulator.m_psxBios->getC0name(i);
            if (!name) {
                name = defaultName;
                std::snprintf(defaultName, 16, "sys_c0_%02x", i);
            }
            if (m_skipBiosUnknowns && isUnknown(name, 'c')) continue;
            char checkboxName[16];
            std::snprintf(checkboxName, 16, "##sys_c0_%02x_brk", i);
            ImGui::Text("%9u", g_emulator.m_psxCpu->getCounters(2)[i]);
            ImGui::SameLine();
            ImGui::Checkbox(checkboxName, &g_emulator.m_psxCpu->m_breakpoints[2][i]);
            ImGui::SameLine();
            ImGui::Text(name);
        }
        ImGui::EndChild();
    }
    ImGui::End();
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
        ImGui::Text(_("OpenGL information"));
        someString(_("vendor"), GL_VENDOR);
        someString(_("renderer"), GL_RENDERER);
        someString(_("version"), GL_VERSION);
        someString(_("shading language version"), GL_SHADING_LANGUAGE_VERSION);
        GLint n, i;
        glGetIntegerv(GL_NUM_EXTENSIONS, &n);
        checkGL();
        ImGui::Text(_("extensions:"));
        ImGui::BeginChild("GLextensions", ImVec2(0, 0), true);
        for (i = 0; i < n; i++) {
            const char* extension = (const char*)glGetStringi(GL_EXTENSIONS, i);
            checkGL();
            ImGui::Text("%s", extension);
        }
        ImGui::EndChild();
    }
    ImGui::End();
}

void PCSX::GUI::update() {
    endFrame();
    startFrame();
    // This scheduling is extremely delicate, because this will cause update to be reentrant.
    // We basically need these to be tail calls, or at least, close from it.
    if (m_scheduleSoftReset) {
        m_scheduleSoftReset = false;
        PCSX::g_emulator.m_psxCpu->psxReset();
    } else if (m_scheduleHardReset) {
        m_scheduleHardReset = false;
        PCSX::g_emulator.EmuReset();
    }
}
