#include <SDL.h>
#include <assert.h>

#include "gui/gui.h"

#include "GL/gl3w.h"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_sdl.h"

static void checkGL() {
    volatile GLenum error = glGetError();
    assert(error == GL_NO_ERROR);
}
static SDL_Window *gWindow = NULL;
static SDL_GLContext gGlcontext = NULL;
static GLuint gEmuTexture = 0;

static void startFrame();
static void endFrame();

unsigned int GUI_init() {
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

    gWindow = SDL_CreateWindow("PCSX-REDUX", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1200, 800,
                               SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    assert(gWindow);

    gGlcontext = SDL_GL_CreateContext(gWindow);
    assert(gGlcontext);

    int result = gl3wInit();

    assert(result == 0);

    // Setup ImGui binding
    ImGui::CreateContext();
    ImGui_ImplOpenGL3_Init();
    ImGui_ImplSDL2_InitForOpenGL(gWindow, gGlcontext);

    glGenTextures(1, &gEmuTexture);

    startFrame();

    return gEmuTexture;
}

static void startFrame() {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        ImGui_ImplSDL2_ProcessEvent(&event);
        if (event.type == SDL_QUIT) exit(0);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL2_NewFrame(gWindow);
    ImGui::NewFrame();
    SDL_GL_SwapWindow(gWindow);
}

static ImVec4 clear_color = ImColor(114, 144, 154);
static void endFrame() {
    // Update the output texture from emulator here
    {
        glBindTexture(GL_TEXTURE_2D, gEmuTexture);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 1024, 512, 0, GL_RGB, GL_UNSIGNED_BYTE, 0);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    }

    glViewport(0, 0, (int)ImGui::GetIO().DisplaySize.x, (int)ImGui::GetIO().DisplaySize.y);
    glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
    glClearDepthf(0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    if (ImGui::BeginMainMenuBar()) {
        ImGui::Text(" %.2f FPS (%.2f ms)", ImGui::GetIO().Framerate, 1000.0f / ImGui::GetIO().Framerate);

        ImGui::EndMainMenuBar();
    }

    ImGui::Begin("Emu output");
    {
        ImVec2 textureSize = ImGui::GetWindowSize();
        textureSize.y = textureSize.x * (512.f / 1024.f);  // TODO: what's the ratio of PSX?
        ImGui::Image((ImTextureID)gEmuTexture, textureSize, ImVec2(0, 0), ImVec2(1, 1));
        ImGui::SameLine();
    }
    ImGui::End();

    ImGui::Begin("blah");
    ImGui::Text("Test");
    ImGui::End();

    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glFlush();
}

void GUI_flip() {
    endFrame();
    startFrame();
}
