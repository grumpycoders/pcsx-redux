#include <SDL.h>
#include <assert.h>

#include <unordered_set>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "gui/gui.h"

#include "GL/gl3w.h"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_sdl.h"

void PCSX::GUI::bindVRAMTexture() {
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    checkGL();
}

void PCSX::GUI::checkGL() {
    volatile GLenum error = glGetError();
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
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_AUDIO) != 0) {
        assert(0);
    }

    // SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_DEBUG_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);

    m_window = SDL_CreateWindow("PCSX-REDUX", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 800,
                                SDL_WINDOW_OPENGL | SDL_WINDOW_ALLOW_HIGHDPI | SDL_WINDOW_RESIZABLE);
    assert(m_window);

    m_glContext = SDL_GL_CreateContext(m_window);
    assert(m_glContext);

    int result = gl3wInit();

    assert(result == 0);

    // Setup ImGui binding
    ImGui::CreateContext();
    ImGui_ImplOpenGL3_Init();
    ImGui_ImplSDL2_InitForOpenGL(m_window, m_glContext);

    glGenTextures(1, &m_VRAMTexture);
    glBindTexture(GL_TEXTURE_2D, m_VRAMTexture);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5, 1024, 512);
    checkGL();

    // offscreen stuff
    glGenFramebuffers(1, &m_offscreenFrameBuffer);
    glGenTextures(2, m_offscreenTextures);
    glGenRenderbuffers(1, &m_offscreenDepthBuffer);
    checkGL();

    startFrame();
    m_currentTexture = 1;
    flip();
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
                _exit(0);
                break;
            case SDL_KEYDOWN:
                if ((mods & KMOD_ALT) && (sc == SDL_SCANCODE_RETURN)) {
                    setFullscreen(!m_fullscreen);
                    passthrough = false;
                } else {
                    keyset.insert(sc);
                }
                break;
        }
        if (passthrough) ImGui_ImplSDL2_ProcessEvent(&event);
    }
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(m_window);
    ImGui::NewFrame();
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

    // made up resolution
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

    glFrontFace(GL_CW);
    glCullFace(GL_BACK);
    glEnable(GL_CULL_FACE);
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
    glClearDepthf(0.f);
    checkGL();
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    checkGL();

    int w, h;
    SDL_GL_GetDrawableSize(m_window, &w, &h);
    m_renderSize = ImVec2(w, h);
    normalizeDimensions(m_renderSize, m_renderRatio);

    if (m_fullscreenRender) {
        ImTextureID texture = ImTextureID(m_offscreenTextures[m_currentTexture]);
        ImGui::SetNextWindowPos(ImVec2((w - m_renderSize.x) / 2.0f, (h - m_renderSize.y) / 2.0f));
        ImGui::SetNextWindowSize(m_renderSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::Begin("FullScreenRender", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                         ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::Image(texture, m_renderSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::End();
        ImGui::PopStyleVar();
        ImGui::PopStyleVar();
    }

    if (m_showMenu || !m_fullscreenRender) {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu("Debug")) {
                ImGui::MenuItem("Show Logs", nullptr, &m_showLog);
                ImGui::MenuItem("Show VRAM", nullptr, &m_showVRAMwindow);
                if (ImGui::BeginMenu("Memory Editors")) {
                    unsigned counter = 1;
                    for (auto& editor : m_mainMemEditors) {
                        std::string title = "Memory Editor #" + std::to_string(counter++);
                        ImGui::MenuItem(title.c_str(), nullptr, &editor.show);
                    }
                    ImGui::EndMenu();
                }
                ImGui::MenuItem("Fullscreen render", nullptr, &m_fullscreenRender);
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("ImGui Demo")) {
                ImGui::MenuItem("Toggle", nullptr, &m_showDemo);
                ImGui::EndMenu();
            }
            ImGui::Text(" %.2f FPS (%.2f ms)", ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);

            ImGui::EndMainMenuBar();
        }
    }

    if (m_showDemo) ImGui::ShowDemoWindow();

    if (m_showVRAMwindow) {
        ImGui::SetNextWindowPos(ImVec2(10, 20), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1024, 512), ImGuiCond_FirstUseEver);
        if (ImGui::Begin("VRAM", &m_showVRAMwindow, ImGuiWindowFlags_NoScrollbar)) {
            ImVec2 textureSize = ImGui::GetWindowSize();
            normalizeDimensions(textureSize, 0.5f);
            ImGui::Image((ImTextureID)m_VRAMTexture, textureSize, ImVec2(0, 0), ImVec2(1, 1));
        }
        ImGui::End();
    }

    if (!m_fullscreenRender) {
        ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(640, 480), ImGuiCond_FirstUseEver);
        ImGui::Begin("Output", nullptr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse);
        ImVec2 textureSize = ImGui::GetWindowSize();
        normalizeDimensions(textureSize, m_renderRatio);
        ImGui::Image((ImTextureID)m_offscreenTextures[m_currentTexture], textureSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::End();
    }

    if (m_showLog) {
        ImGui::SetNextWindowPos(ImVec2(10, 540), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(1200, 250), ImGuiCond_FirstUseEver);
        m_log.draw("Logs", &m_showLog);
    }

    unsigned counter = 1;
    for (auto& editor : m_mainMemEditors) {
        std::string title = "Memory Editor #" + std::to_string(counter++);
        if (editor.show) editor.editor.DrawWindow(title.c_str(), PCSX::g_emulator.m_psxMem->g_psxM, 2 * 1024 * 1024);
    }

    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    checkGL();
    glFlush();
    checkGL();
}
