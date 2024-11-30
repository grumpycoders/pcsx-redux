/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "gui/widgets/shader-editor.h"

#include <filesystem>
#include <fstream>
#include <istream>
#include <ostream>
#include <sstream>
#include <streambuf>

#include "GL/gl3w.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "lua/luawrapper.h"
#include "support/opengl.h"

lua_Number PCSX::Widgets::ShaderEditor::s_index = 0;

static const GLchar *const c_fallbackVertexShader = R"(#version 130
// This is the fallback vertex shader. If you see this, your GPU didn't like the version 300 es one.
precision highp float;
in vec2 Position;
in vec2 UV;
in vec4 Color;
uniform mat4 u_projMatrix;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
    Frag_UV = UV;
    Frag_Color = Color;
    gl_Position = u_projMatrix * vec4(Position.xy, 0, 1);
}
)";

static const GLchar *const c_fallbackPixelShader = R"(#version 130
// This is the fallback pixel shader. If you see this, your GPU didn't like the version 300 es one.
precision highp float;
uniform sampler2D Texture;
in vec2 Frag_UV;
in vec4 Frag_Color;
out vec4 Out_Color;
void main() {
    Out_Color = Frag_Color * texture(Texture, Frag_UV.st);
    Out_Color.a = 1.0;
}
)";

static const GLchar *const c_defaultVertexShader = GL_SHADER_VERSION R"(
// The Vertex Shader isn't necessarily very useful, but is still provided here.
precision highp float;
layout (location = 0) in vec2 Position;
layout (location = 1) in vec2 UV;
layout (location = 2) in vec4 Color;
uniform mat4 u_projMatrix;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
    Frag_UV = UV;
    Frag_Color = Color;
    gl_Position = u_projMatrix * vec4(Position.xy, 0, 1);
}
)";

static const GLchar *const c_defaultPixelShader = GL_SHADER_VERSION R"(
// The Pixel Shader is most likely what the user will want to change.
precision highp float;
uniform sampler2D Texture;
in vec2 Frag_UV;
in vec4 Frag_Color;
layout (location = 0) out vec4 Out_Color;
void main() {
    Out_Color = Frag_Color * texture(Texture, Frag_UV.st);
    Out_Color.a = 1.0;
}
)";

static const char *const c_defaultLuaInvoker = R"(
-- All of this code is sandboxed, as in any global variable it
-- creates will be attached to a local environment. The global
-- environment is still accessible as normal.
-- Note that the environment is wiped every time the shader is
-- recompiled one way or another.

-- The environment will have the `shaderProgramID` variable set
-- before being evaluated, meaning this code is perfectly valid:
function Constructor(shaderProgramID)
    -- Cache some Shader Attributes locations
    print('Shader compiled: program ID = ' .. shaderProgramID)
end
Constructor(shaderProgramID)

-- This function is called to issue an ImGui::Image when it's time
-- to display the video output of the emulated screen. It can
-- prepare some values to later attach to the shader program.
--
-- This function won't be called for non-ImGui renders, such as
-- the offscreen render of the vram.
function Image(textureID, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
    imgui.Image(textureID, dstSizeX, dstSizeY, 0, 0, 1, 1)
end

-- This function is called to draw some UI, at the same time
-- as the shader editor, but regardless of the status of the
-- shader editor window. Its purpose is to potentially display
-- a piece of UI to let the user interact with the shader program.

-- Returning true from it will cause the environment to be saved.
function Draw()
end

-- This function is called just before executing the shader program,
-- to give it a chance to bind some attributes to it, that'd come
-- from either the global state, or the locally computed attributes
-- from the two functions above.
--
-- The last six parameters will only exist for non-ImGui renders.
function BindAttributes(textureID, shaderProgramID, srcLocX, srcLocY, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
end
)";

static const GLchar *const c_24bppConversionFragShader = GL_SHADER_VERSION R"(
uniform sampler2D Texture;
in vec2 Frag_UV;
in vec4 Frag_Color;
layout (location = 0) out vec4 Out_Color;

uniform vec2 u_startCoords;

int floatToU5(float f) {
    return int(floor(f * 31.0 + 0.5));
 }

uint sample16(ivec2 coords) {
    vec4 colour = texelFetch(Texture, coords, 0);
    int r = floatToU5(colour.r);
    int g = floatToU5(colour.g);
    int b = floatToU5(colour.b);
    int msb = int(ceil(colour.a)) << 15;
    return uint(r | (g << 5) | (b << 10) | msb);
}

void main() {
    ivec2 iUV = ivec2(floor((Frag_UV * vec2(1024.f, 512.f))));
    ivec2 startCoords = (iUV.x >= 512) ? ivec2(512, 0) : ivec2(0); // TODO: uniform
    ivec2 icoords = iUV - startCoords;

    int x = startCoords.x + (icoords.x * 3) / 2;
    int y = startCoords.y + icoords.y;
    iUV = ivec2(x, y);

    const ivec2 size = ivec2(1023, 511);

    uint s0 = sample16(iUV & size);
    uint s1 = sample16((iUV + ivec2(1, 0)) & size);

    uint fullSample = ((s1 << 16) | s0) >> ((icoords.x & 1) * 8);
    uint r = fullSample & 0xffu;
    uint g = (fullSample >> 8u) & 0xffu;
    uint b = (fullSample >> 16u) & 0xffu;

    vec3 col = vec3(ivec3(r, g, b)) / 255.0;
    Out_Color = vec4(col, 1.0);
}
)";

PCSX::Widgets::ShaderEditor::ShaderEditor(const std::string &base, const std::string_view &dVS,
                                          const std::string_view &dPS, const std::string_view &dL)
    : m_baseFilename(base), m_index(++s_index) {
    std::filesystem::path f = base;
    if (f.is_relative()) {
        f = g_system->getPersistentDir() / f;
    }
    {
        f.replace_extension("vert");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_vertexShaderEditor.setText(code.str());
        } else {
            std::string code(dVS);
            m_vertexShaderEditor.setText(code.c_str());
        }
    }
    {
        f.replace_extension("frag");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_pixelShaderEditor.setText(code.str());
        } else {
            std::string code(dPS);
            m_pixelShaderEditor.setText(code.c_str());
        }
    }
    {
        f.replace_extension("lua");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_luaEditor.setText(code.str());
        } else {
            std::string code(dL);
            m_luaEditor.setText(code.c_str());
        }
    }
}

PCSX::Widgets::ShaderEditor::ShaderEditor(const std::string &base) : m_baseFilename(base), m_index(++s_index) {
    setDefaults();
    std::filesystem::path f = base;
    if (f.is_relative()) {
        f = g_system->getPersistentDir() / f;
    }
    {
        f.replace_extension("vert");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_vertexShaderEditor.setText(code.str());
        }
    }
    {
        f.replace_extension("frag");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_pixelShaderEditor.setText(code.str());
        }
    }
    {
        f.replace_extension("lua");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_luaEditor.setText(code.str());
        }
    }
}

PCSX::Widgets::ShaderEditor::~ShaderEditor() {
    if (m_shaderProgram != 0) {
        glDeleteProgram(m_shaderProgram);
    }
}

void PCSX::Widgets::ShaderEditor::setDefaults() {
    m_vertexShaderEditor.setText(c_defaultVertexShader);
    m_pixelShaderEditor.setText(c_defaultPixelShader);
    m_luaEditor.setText(c_defaultLuaInvoker);
}

void PCSX::Widgets::ShaderEditor::setFallbacks() {
    m_vertexShaderEditor.setText(c_fallbackVertexShader);
    m_pixelShaderEditor.setText(c_fallbackPixelShader);
    m_luaEditor.setText(c_defaultLuaInvoker);
}

void PCSX::Widgets::ShaderEditor::init() {
    m_vao.create();
    m_vbo.createFixedSize(sizeof(VertexData) * 4, GL_STATIC_DRAW);

    m_quadVertices[0].positions[0] = -1.0;
    m_quadVertices[0].positions[1] = -1.0;
    m_quadVertices[1].positions[0] = 1.0;
    m_quadVertices[1].positions[1] = -1.0;
    m_quadVertices[2].positions[0] = -1.0;
    m_quadVertices[2].positions[1] = 1.0;
    m_quadVertices[3].positions[0] = 1.0;
    m_quadVertices[3].positions[1] = 1.0;
}

PCSX::OpenGL::Status PCSX::Widgets::ShaderEditor::compile(GUI *gui,
                                                          const std::vector<std::string_view> &mandatoryAttributes) {
    m_setupVAO = true;
    m_shaderProjMtxLoc = -1;
    GLint status = 0;
    GUI::ScopedOnlyLog scopedOnlyLog(gui);

    GLuint vertexShader = glCreateShader(GL_VERTEX_SHADER);
    auto VS = getVertexText();
    const char *VSv = VS.data();
    glShaderSource(vertexShader, 1, &VSv, 0);
    glCompileShader(vertexShader);

    glGetShaderiv(vertexShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(vertexShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);
        glGetShaderInfoLog(vertexShader, maxLength, &maxLength, log);

        m_errorMessage = fmt::format(f_("Vertex Shader compilation error: {}\n"), log);

        free(log);
        glDeleteShader(vertexShader);
        return OpenGL::Status::makeError(m_errorMessage);
    }

    GLuint pixelShader = glCreateShader(GL_FRAGMENT_SHADER);
    auto PS = getPixelText();
    const char *PSv = PS.data();
    glShaderSource(pixelShader, 1, &PSv, 0);
    glCompileShader(pixelShader);

    glGetShaderiv(pixelShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(pixelShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetShaderInfoLog(pixelShader, maxLength, &maxLength, log);

        m_errorMessage = fmt::format(f_("Pixel Shader compilation error: {}\n"), log);

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        return OpenGL::Status::makeError(m_errorMessage);
    }

    GLuint shaderProgram = glCreateProgram();
    glAttachShader(shaderProgram, vertexShader);
    glAttachShader(shaderProgram, pixelShader);

    glLinkProgram(shaderProgram);

    glGetProgramiv(shaderProgram, GL_LINK_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetProgramiv(shaderProgram, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetProgramInfoLog(shaderProgram, maxLength, &maxLength, log);

        m_errorMessage = fmt::format(f_("Link error: {}\n"), log);

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        return OpenGL::Status::makeError(m_errorMessage);
    }

    for (auto attrib : mandatoryAttributes) {
        int loc = glGetAttribLocation(shaderProgram, attrib.data());
        if (loc == -1) {
            m_errorMessage = fmt::format(f_("Missing attribute {} in shader program"), attrib);
            glDeleteProgram(shaderProgram);
            glDeleteShader(vertexShader);
            glDeleteShader(pixelShader);
            return OpenGL::Status::makeError(m_errorMessage);
        }
    }

    glDeleteShader(vertexShader);
    glDeleteShader(pixelShader);

    m_errorMessage.clear();
    gui->getGLerrors();

    auto L = *g_emulator->m_lua;
    std::filesystem::path f = m_baseFilename;
    if (f.is_relative()) {
        f = g_system->getPersistentDir() / f;
    }

    if (m_autocompile) {
        m_lastLuaErrors.clear();
        auto oldNormalPrinter = L.normalPrinter;
        auto oldErrorPrinter = L.errorPrinter;
        L.normalPrinter = [](std::string_view) {};
        L.errorPrinter = [this](std::string_view msg) { m_lastLuaErrors.push_back(std::string(msg)); };
        int top = L.gettop();
        // grabbing the table where we'll store our shader invoker
        getRegistry(L);
        // each ShaderEditor has its own constant index for this table
        L.push(m_index);
        // this table will contain the sandbox environment
        L.newtable();
        // assign _G to __index's metatable
        if (L.newmetatable("SHADER_EDITOR_METATABLE")) {
            L.push("__index");
            L.push("_G");
            L.gettable(LUA_GLOBALSINDEX);
            L.settable();
        }
        L.setmetatable();
        L.push("shaderProgramID");
        L.push(static_cast<lua_Number>(shaderProgram));
        L.settable();
        try {
            f.replace_extension("lua");
            L.load(getLuaText(), f.string().c_str(), false);
            // assign our sandbox as the global environment of this new piece of code
            L.copy(-2);
            L.setfenv();
            // and evaluate it
            L.pcall();
            bool gotGLerror = false;
            auto errors = gui->getGLerrors();
            for (const auto &error : errors) {
                m_lastLuaErrors.push_back(error);
                gotGLerror = true;
            }
            if (!gotGLerror) {
                m_displayError = false;
                // if no error, reload settings
                json settings;
                try {
                    f.replace_extension("json");
                    std::ifstream in(f);
                    if (in.is_open()) {
                        in >> settings;
                    }
                } catch (...) {
                }
                L.fromJson(settings);

                // and remember the newest Lua code
                L.settable();
            }
        } catch (...) {
            m_displayError = true;
        }
        while (top < L.gettop()) {
            L.pop();
        }
        L.normalPrinter = oldNormalPrinter;
        L.errorPrinter = oldErrorPrinter;
    }

    if (m_autosave) {
        {
            f.replace_extension("vert");
            std::ofstream out(f, std::ofstream::out);
            out << m_vertexShaderEditor.getText();
        }
        {
            f.replace_extension("frag");
            std::ofstream out(f, std::ofstream::out);
            out << m_pixelShaderEditor.getText();
        }
        {
            f.replace_extension("lua");
            std::ofstream out(f, std::ofstream::out);
            out << m_luaEditor.getText();
        }
    }

    if (m_shaderProgram != 0) {
        glDeleteProgram(m_shaderProgram);
    }
    m_shaderProgram = shaderProgram;
    m_shaderProjMtxLoc = glGetUniformLocation(m_shaderProgram, "u_projMatrix");
    return OpenGL::Status::makeOk();
}

bool PCSX::Widgets::ShaderEditor::draw(GUI *gui, const char *title) {
    if (!ImGui::Begin(title, &m_show)) return false;
    ImGui::Checkbox(_("Auto compile"), &m_autocompile);
    ImGui::SameLine();
    ImGui::Checkbox(_("Auto save"), &m_autosave);
    ImGui::SameLine();
    ImGui::Checkbox(_("Show all"), &m_showAll);
    ImGui::SameLine();
    if (ImGui::Button(_("Configure shader"))) {
        setConfigure();
    }
    auto contents = ImGui::GetContentRegionAvail();
    ImGuiStyle &style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = heightSeparator * 2 + 5 * ImGui::GetTextLineHeightWithSpacing();
    float width = contents.x / 3 - style.ItemInnerSpacing.x;
    gui->useMonoFont();
    if (m_showAll) {
        ImVec2 size = {width, contents.y - footerHeight};
        ImGui::BeginChild("VertexShaderEditor", size);
        m_vertexShaderEditor.draw(gui);
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("PixelShaderEditor", size);
        m_pixelShaderEditor.draw(gui);
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("LuaInvoker", size);
        m_luaEditor.draw(gui);
        ImGui::EndChild();
    } else {
        if (ImGui::BeginTabBar("MyTabBar")) {
            ImVec2 size = {contents.x, contents.y - footerHeight};
            if (ImGui::BeginTabItem(_("Vertex Shader"))) {
                ImGui::BeginChild("VertexShaderEditor", size);
                m_vertexShaderEditor.draw(gui);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Pixel Shader"))) {
                ImGui::BeginChild("PixelShaderEditor", size);
                m_pixelShaderEditor.draw(gui);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Lua Invoker"))) {
                ImGui::BeginChild("LuaInvoker", size);
                m_luaEditor.draw(gui);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::PopFont();
    ImGui::BeginChild("Errors", ImVec2(0, 0), true);
    ImGui::Text("%s", m_errorMessage.c_str());
    if (m_displayError) {
        for (auto &msg : m_lastLuaErrors) {
            ImGui::TextUnformatted(msg.c_str());
        }
    }
    ImGui::EndChild();

    ImGui::End();

    return m_vertexShaderEditor.hasTextChanged() || m_pixelShaderEditor.hasTextChanged() ||
           m_luaEditor.hasTextChanged();
}

void PCSX::Widgets::ShaderEditor::setConfigure(bool configure) {
    auto L = *g_emulator->m_lua;
    int top = L.gettop();
    getRegistry(L);
    L.push(m_index);
    L.gettable();
    L.push("configureme");
    L.push(configure);
    L.settable();
    while (top < L.gettop()) {
        L.pop();
    }
}

void PCSX::Widgets::ShaderEditor::configure(GUI *gui) {
    auto Lorg = *g_emulator->m_lua;
    {
        int top = Lorg.gettop();
        auto L = Lorg.thread();
        getRegistry(L);
        L.push(m_index);
        L.gettable();
        if (L.istable()) {
            L.push("Draw");
            L.gettable();
            if (L.isfunction()) {
                L.copy(-2);
                L.setfenv();
                GUI::ScopedOnlyLog scopedOnlyLog(gui);
                try {
                    int top = L.gettop() - 1;
                    L.pcall();
                    bool gotGLerror = false;
                    auto errors = gui->getGLerrors();
                    for (const auto &error : errors) {
                        m_lastLuaErrors.push_back(error);
                        gotGLerror = true;
                    }
                    if (gotGLerror) throw("OpenGL error while running Lua code");

                    if (top != L.gettop()) {
                        bool changed = L.toboolean(top + 1);
                        if (changed) {
                            auto j = L.toJson(-2);
                            if (j.is_object()) {
                                auto i = j.find("shaderProgramID");
                                if (i != j.end()) j.erase(i);
                            }
                            std::filesystem::path f = m_baseFilename;
                            f.replace_extension("json");
                            std::ofstream out(f, std::ofstream::out);
                            out << std::setw(2) << j << std::endl;
                        }
                    }
                } catch (...) {
                    getRegistry(Lorg);
                    Lorg.push(m_index);
                    Lorg.gettable();
                    Lorg.push("Draw");
                    Lorg.push();
                    Lorg.settable();
                }
            }
        }
        while (top < Lorg.gettop()) {
            Lorg.pop();
        }
    }
}

void PCSX::Widgets::ShaderEditor::reset(GUI *gui) {
    auto Lorg = *g_emulator->m_lua;
    {
        int top = Lorg.gettop();
        auto L = Lorg.thread();
        getRegistry(L);
        L.push(m_index);
        L.gettable();
        if (L.istable()) {
            L.push("Reset");
            L.gettable();
            if (L.isfunction()) {
                L.copy(-2);
                L.setfenv();
                GUI::ScopedOnlyLog scopedOnlyLog(gui);
                try {
                    L.pcall();
                    bool gotGLerror = false;
                    auto errors = gui->getGLerrors();
                    for (const auto &error : errors) {
                        m_lastLuaErrors.push_back(error);
                        gotGLerror = true;
                    }
                    if (gotGLerror) throw("OpenGL error while running Lua code");
                } catch (...) {
                    getRegistry(Lorg);
                    Lorg.push(m_index);
                    Lorg.gettable();
                    Lorg.push("Reset");
                    Lorg.push();
                    Lorg.settable();
                }
            }
        }
        while (top < Lorg.gettop()) {
            Lorg.pop();
        }
    }
}

void PCSX::Widgets::ShaderEditor::getRegistry(Lua L) {
    L.push("SHADER_EDITOR");
    L.gettable(LUA_REGISTRYINDEX);
    if (L.isnil()) {
        L.pop();
        L.newtable();
        L.push("SHADER_EDITOR");
        L.copy(-2);
        L.settable(LUA_REGISTRYINDEX);
    }
}

void PCSX::Widgets::ShaderEditor::renderWithImgui(GUI *gui, ImTextureID textureID, const ImVec2 &srcSize,
                                                  const ImVec2 &dstSize) {
    if (m_shaderProgram == 0) {
        compile(gui);
    }
    if (m_shaderProgram == 0) {
        ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
        return;
    }

    ImDrawList *drawList = ImGui::GetWindowDrawList();
    m_cachedGui = gui;
    drawList->AddCallback(
        [](const ImDrawList *parentList, const ImDrawCmd *cmd) {
            ShaderEditor *that = reinterpret_cast<ShaderEditor *>(cmd->UserCallbackData);
            that->imguiCB(parentList, cmd);
        },
        this);

    auto Lorg = *g_emulator->m_lua;
    {
        int top = Lorg.gettop();
        auto L = Lorg.thread();
        getRegistry(L);
        L.push(m_index);
        L.gettable();
        if (L.isnil() || !L.istable()) {
            ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
        } else {
            L.push("Image");
            L.gettable();
            if (L.isfunction()) {
                L.copy(-2);
                L.setfenv();
                L.push(static_cast<lua_Number>(textureID));
                L.push(srcSize.x);
                L.push(srcSize.y);
                L.push(dstSize.x);
                L.push(dstSize.y);
                GUI::ScopedOnlyLog scopedOnlyLog(gui);
                try {
                    L.pcall(5);
                    bool gotGLerror = false;
                    auto errors = gui->getGLerrors();
                    for (const auto &error : errors) {
                        m_lastLuaErrors.push_back(error);
                        gotGLerror = true;
                    }
                    if (gotGLerror) throw("OpenGL error while running Lua code");
                } catch (...) {
                    getRegistry(Lorg);
                    Lorg.push(m_index);
                    Lorg.gettable();
                    Lorg.push("Image");
                    Lorg.push();
                    Lorg.settable();
                }
            } else {
                ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
            }
        }
        while (top < Lorg.gettop()) {
            Lorg.pop();
        }
    }

    drawList->AddCallback(
        [](const ImDrawList *parentList, const ImDrawCmd *cmd) {
            ShaderEditor *that = reinterpret_cast<ShaderEditor *>(cmd->UserCallbackData);
            glUseProgram(that->m_imguiProgram);
        },
        this);
}

void PCSX::Widgets::ShaderEditor::imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    GLuint textureID = static_cast<GLuint>(cmd->TextureId);

    GLfloat projMtx[4][4];
    if (m_imguiProjMtxLoc == -1) {
        glGetIntegerv(GL_CURRENT_PROGRAM, &m_imguiProgram);
        m_imguiProjMtxLoc = glGetUniformLocation(m_imguiProgram, "ProjMtx");
    }

    // Get projection matrix from the Imgui program
    glUseProgram(m_shaderProgram);
    glGetUniformfv(m_imguiProgram, m_imguiProjMtxLoc, &projMtx[0][0]);

    // Send projection matrix to our shader
    glUniformMatrix4fv(m_shaderProjMtxLoc, 1, GL_FALSE, &projMtx[0][0]);

    auto Lorg = *g_emulator->m_lua;
    {
        int top = Lorg.gettop();
        auto L = Lorg.thread();
        getRegistry(L);
        L.push(m_index);
        L.gettable();
        if (L.istable()) {
            L.push("BindAttributes");
            L.gettable();
            if (L.isfunction()) {
                {
                    Lorg.push("SHADER_EDITOR");
                    Lorg.gettable(LUA_REGISTRYINDEX);
                    Lorg.push("imgui");
                    Lorg.copy();
                    Lorg.copy();
                    Lorg.gettable(LUA_GLOBALSINDEX);
                    Lorg.settable(-4);
                    Lorg.push();
                    Lorg.settable(LUA_GLOBALSINDEX);
                    Lorg.pop();
                }
                L.copy(-2);
                L.setfenv();
                L.push(lua_Number(textureID));
                L.push(lua_Number(m_shaderProgram));
                GUI::ScopedOnlyLog scopedOnlyLog(m_cachedGui);
                try {
                    L.pcall(2);
                    bool gotGLerror = false;
                    auto errors = m_cachedGui->getGLerrors();
                    for (const auto &error : errors) {
                        m_lastLuaErrors.push_back(error);
                        gotGLerror = true;
                    }
                    if (gotGLerror) throw("OpenGL error while running Lua code");
                } catch (...) {
                    getRegistry(Lorg);
                    Lorg.push(m_index);
                    Lorg.gettable();
                    Lorg.push("BindAttributes");
                    Lorg.push();
                    Lorg.settable();
                }
                {
                    Lorg.push("SHADER_EDITOR");
                    Lorg.gettable(LUA_REGISTRYINDEX);
                    Lorg.push("imgui");
                    Lorg.copy();
                    Lorg.gettable(-3);
                    Lorg.settable(LUA_GLOBALSINDEX);
                    Lorg.pop();
                }
            }
        }
        while (top < Lorg.gettop()) {
            Lorg.pop();
        }
    }
}

void PCSX::Widgets::ShaderEditor::render(GUI *gui, GLuint textureID, const ImVec2 &srcLoc, const ImVec2 &srcSize,
                                         const ImVec2 &dstSize, std::initializer_list<lua_Number> extraArgs) {
    if (m_shaderProgram == 0) {
        compile(gui);
    }
    if (m_shaderProgram == 0) {
        return;
    }

    m_vao.bind();
    glUseProgram(m_shaderProgram);

    m_quadVertices[0].textures[0] = srcLoc.x;
    m_quadVertices[0].textures[1] = srcLoc.y;

    m_quadVertices[1].textures[0] = srcLoc.x + srcSize.x;
    m_quadVertices[1].textures[1] = srcLoc.y;

    m_quadVertices[2].textures[0] = srcLoc.x;
    m_quadVertices[2].textures[1] = srcLoc.y + srcSize.y;

    m_quadVertices[3].textures[0] = srcLoc.x + srcSize.x;
    m_quadVertices[3].textures[1] = srcLoc.y + srcSize.y;

    m_vbo.bind();
    m_vbo.bufferVertsSub(m_quadVertices, 4);
    glDisable(GL_DEPTH_TEST);

    if (m_setupVAO) {
        m_setupVAO = false;
        int loc = glGetAttribLocation(m_shaderProgram, "Position");
        if (loc >= 0) {
            glVertexAttribPointer(loc, 2, GL_FLOAT, GL_FALSE, sizeof(VertexData),
                                  (void *)&((VertexData *)nullptr)->positions);
            glEnableVertexAttribArray(loc);
        }

        loc = glGetAttribLocation(m_shaderProgram, "UV");
        if (loc >= 0) {
            glVertexAttribPointer(loc, 2, GL_FLOAT, GL_FALSE, sizeof(VertexData),
                                  (void *)&((VertexData *)nullptr)->textures);
            glEnableVertexAttribArray(loc);
        }

        loc = glGetAttribLocation(m_shaderProgram, "Color");
        if (loc >= 0) {
            glVertexAttribPointer(loc, 4, GL_FLOAT, GL_FALSE, sizeof(VertexData),
                                  (void *)&((VertexData *)nullptr)->color);
            glEnableVertexAttribArray(loc);
        }
    }

    static constexpr float currentProjection[4][4] = {
        {1.0f, 0.0f, 0.0f, 0.0f},
        {0.0f, 1.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 1.0f, 0.0f},
        {0.0f, 0.0f, 0.0f, 1.0f},
    };
    glUniformMatrix4fv(m_shaderProjMtxLoc, 1, GL_FALSE, &currentProjection[0][0]);

    glBindTexture(GL_TEXTURE_2D, textureID);

    auto Lorg = *g_emulator->m_lua;
    {
        int top = Lorg.gettop();
        auto L = Lorg.thread();
        getRegistry(L);
        L.push(m_index);
        L.gettable();
        if (L.istable()) {
            L.push("BindAttributes");
            L.gettable();
            if (L.isfunction()) {
                L.copy(-2);
                L.setfenv();
                L.push(static_cast<lua_Number>(textureID));
                L.push(lua_Number(m_shaderProgram));
                L.push(srcLoc.x);
                L.push(srcLoc.y);
                L.push(srcSize.x);
                L.push(srcSize.y);
                L.push(dstSize.x);
                L.push(dstSize.y);
                for (auto arg : extraArgs) {
                    L.push(arg);
                }
                GUI::ScopedOnlyLog scopedOnlyLog(gui);
                try {
                    L.pcall(8 + extraArgs.size());
                    bool gotGLerror = false;
                    auto errors = gui->getGLerrors();
                    for (const auto &error : errors) {
                        m_lastLuaErrors.push_back(error);
                        gotGLerror = true;
                    }
                    if (gotGLerror) throw("OpenGL error while running Lua code");
                } catch (...) {
                    getRegistry(Lorg);
                    Lorg.push(m_index);
                    Lorg.gettable();
                    Lorg.push("BindAttributes");
                    Lorg.push();
                    Lorg.settable();
                }
            }
        }
        while (top < Lorg.gettop()) {
            Lorg.pop();
        }
    }

    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}
