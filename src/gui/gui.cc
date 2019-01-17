#include <SDL.h>
#include <assert.h>

#include "gui/gui.h"

#include "GL/gl3w.h"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_sdl.h"

void PCSX::GUI::bindVRAMTexture() {
    glBindTexture(GL_TEXTURE_2D, s_VRAMTexture);
    checkGL();
}

void PCSX::GUI::checkGL() {
    volatile GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        SDL_TriggerBreakpoint();
        abort();
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

    SDL_Rect r;
    if (SDL_GetDisplayBounds(0, &r) != 0) abort();
    s_window = SDL_CreateWindow("PCSX-REDUX", 0, 0, r.w, r.h,
                               SDL_WINDOW_OPENGL | SDL_WINDOW_ALLOW_HIGHDPI | SDL_WINDOW_BORDERLESS);
    assert(s_window);

    s_glContext = SDL_GL_CreateContext(s_window);
    assert(s_glContext);

    int result = gl3wInit();

    assert(result == 0);

    // Setup ImGui binding
    ImGui::CreateContext();
    ImGui_ImplOpenGL3_Init();
    ImGui_ImplSDL2_InitForOpenGL(s_window, s_glContext);

    glGenTextures(1, &s_VRAMTexture);
    glBindTexture(GL_TEXTURE_2D, s_VRAMTexture);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5, 1024, 512);
    checkGL();

    // offscreen stuff
    glGenFramebuffers(1, &s_offscreenFrameBuffer);
    glGenTextures(2, s_offscreenTextures);
    glGenRenderbuffers(1, &s_offscreenDepthBuffer);
    checkGL();

    startFrame();
    s_currentTexture = 1;
    flip();
}

void PCSX::GUI::startFrame() {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        ImGui_ImplSDL2_ProcessEvent(&event);
        if (event.type == SDL_QUIT) _exit(0);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(s_window);
    ImGui::NewFrame();
    SDL_GL_SwapWindow(s_window);
    glBindFramebuffer(GL_FRAMEBUFFER, s_offscreenFrameBuffer);
    checkGL();
}

void PCSX::GUI::flip() {
    checkGL();
    int resolution[2] = {1024, 1024};

    glBindFramebuffer(GL_FRAMEBUFFER, s_offscreenFrameBuffer);
    checkGL();
    glBindTexture(GL_TEXTURE_2D, s_offscreenTextures[s_currentTexture]);
    checkGL();

    // made up resolution
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, resolution[0], resolution[1], 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    checkGL();

    glBindRenderbuffer(GL_RENDERBUFFER, s_offscreenDepthBuffer);
    checkGL();
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH_COMPONENT24, resolution[0], resolution[1]);
    checkGL();
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_RENDERBUFFER, s_offscreenDepthBuffer);
    checkGL();
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, s_offscreenTextures[s_currentTexture], 0);
    checkGL();
    GLenum DrawBuffers[1] = {GL_COLOR_ATTACHMENT0};

    glDrawBuffers(1, DrawBuffers);  // "1" is the size of DrawBuffers
    checkGL();

    assert(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);

    glViewport(0, 0, resolution[0], resolution[1]);

    glClearColor(0, 0, 0, 0);
    glClearDepthf(0.f);

    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    glFrontFace(GL_CW);
    glCullFace(GL_BACK);
    glEnable(GL_CULL_FACE);
    checkGL();

    glClearColor(1, 0, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);

    glDisable(GL_CULL_FACE);
    s_currentTexture = s_currentTexture ? 0 : 1;
    checkGL();
}

void PCSX::GUI::endFrame() {
    // bind back the output frame buffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    checkGL();

    glViewport(0, 0, (int)ImGui::GetIO().DisplaySize.x, (int)ImGui::GetIO().DisplaySize.y);
    checkGL();
    glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
    checkGL();
    glClearDepthf(0.f);
    checkGL();
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    checkGL();

    if (ImGui::BeginMainMenuBar()) {
        ImGui::Text(" %.2f FPS (%.2f ms)", ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);

        ImGui::EndMainMenuBar();
    }
    checkGL();

    ImGui::Begin("VRAM");
    {
        ImVec2 textureSize = ImGui::GetWindowSize();
        textureSize.y = textureSize.x * (512.f / 1024.f);
        ImGui::Image((ImTextureID)s_VRAMTexture, textureSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::SameLine();
    }
    ImGui::End();
    checkGL();

    ImGui::Begin("Output");
    {
        ImVec2 textureSize = ImGui::GetWindowSize();
        textureSize.y = textureSize.x * (1024 / 1024.f);
        ImGui::Image((ImTextureID)s_offscreenTextures[s_currentTexture], textureSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::SameLine();
    }
    ImGui::End();
    checkGL();

    ImGui::Begin("blah");
    ImGui::Text("Test");
    ImGui::End();
    checkGL();

    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    checkGL();
    glFlush();
    checkGL();
}

void PCSX::GUI::update() {
    endFrame();
    startFrame();
}
