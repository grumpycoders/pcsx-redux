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

lua_Number PCSX::Widgets::ShaderEditor::s_index = 0;

static const GLchar *const c_defaultVertexShader = GL_SHADER_VERSION R"(
/* The Vertex Shader isn't necessarily very useful, but is still provided here. */
precision mediump float;
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
})";

static const GLchar *const c_defaultPixelShader = GL_SHADER_VERSION R"(
/* The Pixel Shader is most likely what the user will want to change. */
precision mediump float;
uniform sampler2D Texture;
in vec2 Frag_UV;
in vec4 Frag_Color;
layout (location = 0) out vec4 Out_Color;
void main() {
    Out_Color = Frag_Color * texture(Texture, Frag_UV.st);
})";

static const char *const c_defaultLuaInvoker = R"(
-- All of this code is sandboxed, as in any global variable it
-- creates will be attached to a local environment. The global
-- environment is still accessible as normal.

-- This function is called to issue an ImGui::Image when it's time
-- to display the video output of the emulated screen. It can
-- prepare some values to later attach to the shader program.
function Image(textureID, srcSizeX, srcSizeY, dstSizeX, dstSizeY)
    imgui.Image(textureID, dstSizeX, dstSizeY, 0, 0, 1, 1)
end

-- This function is called to draw some UI, at the same time
-- as the shader editor, but regardless of the status of the
-- shader editor window. Its purpose is to potentially display
-- a piece of UI to let the user interact with the shader program.
function Draw()
end

-- This function is called just before executing the shader program,
-- to give it a chance to bind some attributes to it, that'd come
-- from either the global state, or the locally computed attributes
-- from the two functions above.
function BindAttributes(textureID, shaderProgramID)
end
)";

PCSX::Widgets::ShaderEditor::ShaderEditor(const std::string &base, std::string_view dVS, std::string_view dPS,
                                          std::string_view dL)
    : m_baseFilename(base), m_index(++s_index) {
    std::filesystem::path f = base;
    {
        f.replace_extension("glslv");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_vertexShaderEditor.SetText(code.str());
        } else {
            m_vertexShaderEditor.SetText(c_defaultVertexShader);
        }
        m_vertexShaderEditor.SetLanguageDefinition(TextEditor::LanguageDefinition::GLSL());
    }
    {
        f.replace_extension("glslp");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_pixelShaderEditor.SetText(code.str());
        } else {
            m_pixelShaderEditor.SetText(c_defaultPixelShader);
        }
        m_pixelShaderEditor.SetLanguageDefinition(TextEditor::LanguageDefinition::GLSL());
    }
    {
        f.replace_extension("lua");
        std::ifstream in(f, std::ifstream::in);
        if (in) {
            std::ostringstream code;
            code << in.rdbuf();
            in.close();
            m_luaEditor.SetText(code.str());
        } else {
            m_luaEditor.SetText(c_defaultLuaInvoker);
        }
        m_luaEditor.SetLanguageDefinition(TextEditor::LanguageDefinition::Lua());
    }
}

std::optional<GLuint> PCSX::Widgets::ShaderEditor::compile(const std::vector<std::string_view> &mandatoryAttributes) {
    GLint status = 0;

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

        m_errorMessage = fmt::format(_("Vertex Shader compilation error: {}\n"), log);

        free(log);
        glDeleteShader(vertexShader);
        PCSX::GUI::checkGL();
        return std::nullopt;
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

        m_errorMessage = fmt::format(_("Pixel Shader compilation error: {}\n"), log);

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        PCSX::GUI::checkGL();
        return std::nullopt;
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

        m_errorMessage = fmt::format(_("Link error: {}\n"), log);

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        PCSX::GUI::checkGL();
        return std::nullopt;
    }

    for (auto attrib : mandatoryAttributes) {
        int loc = glGetAttribLocation(shaderProgram, attrib.data());
        if (loc == -1) {
            m_errorMessage = fmt::format(_("Missing attribute {} in shader program"), attrib);
            glDeleteProgram(shaderProgram);
            glDeleteShader(vertexShader);
            glDeleteShader(pixelShader);
            PCSX::GUI::checkGL();
            return std::nullopt;
        }
    }

    glDeleteShader(vertexShader);
    glDeleteShader(pixelShader);

    m_errorMessage.clear();

    auto &L = g_emulator->m_lua;
    std::filesystem::path f = m_baseFilename;

    if (m_autoreload) {
        m_lastLuaErrors.clear();
        auto oldNormalPrinter = L->normalPrinter;
        auto oldErrorPrinter = L->errorPrinter;
        L->normalPrinter = [](const std::string &) {};
        L->errorPrinter = [this](const std::string &msg) { m_lastLuaErrors.push_back(msg); };
        int top = L->gettop();
        // grabbing the table where we'll store our shader invoker
        getRegistry(L);
        // each ShaderEditor has its own constant index for this table
        L->push(m_index);
        // this table will contain the sandbox environment
        L->newtable();
        // assign _G to __index's metatable
        if (L->newmetatable("SHADER_EDITOR_METATABLE")) {
            L->push("__index");
            L->push("_G");
            L->gettable(LUA_GLOBALSINDEX);
            L->settable();
        }
        L->setmetatable();
        try {
            f.replace_extension("lua");
            L->load(getLuaText(), f.string().c_str(), false);
            // assign our sandbox as the global environment of this new piece of code
            L->copy(-2);
            L->setfenv();
            // and evaluate it
            L->pcall();
            bool gotGLerror = false;
            GLenum glError = GL_NO_ERROR;
            while ((glError = glGetError()) != GL_NO_ERROR) {
                std::string msg = "glError from Lua: ";
                msg += PCSX::GUI::glErrorToString(glError);
                m_lastLuaErrors.push_back(msg);
                gotGLerror = true;
            }
            if (!gotGLerror) {
                m_displayError = false;
                // if no error, remember the newest Lua code
                L->settable();
            }
        } catch (...) {
            m_displayError = true;
        }
        while (top < L->gettop()) {
            L->pop();
        }
        L->normalPrinter = oldNormalPrinter;
        L->errorPrinter = oldErrorPrinter;
    }

    if (m_autosave) {
        {
            f.replace_extension("glslv");
            std::ofstream out(f, std::ofstream::out);
            out << m_vertexShaderEditor.GetText();
        }
        {
            f.replace_extension("glslp");
            std::ofstream out(f, std::ofstream::out);
            out << m_pixelShaderEditor.GetText();
        }
        {
            f.replace_extension("lua");
            std::ofstream out(f, std::ofstream::out);
            out << m_luaEditor.GetText();
        }
    }

    if (m_shaderProgram != 0) {
        glDeleteProgram(m_shaderProgram);
    }
    m_shaderProgram = shaderProgram;
    return shaderProgram;
}

bool PCSX::Widgets::ShaderEditor::draw(std::string_view title, GUI *gui) {
    auto &L = g_emulator->m_lua;
    int top = L->gettop();
    getRegistry(L);
    L->push(m_index);
    L->gettable();
    if (L->istable()) {
        L->push("Draw");
        L->gettable();
        if (L->isfunction()) {
            L->copy(-2);
            L->setfenv();
            try {
                L->pcall();
                bool gotGLerror = false;
                GLenum glError = GL_NO_ERROR;
                while ((glError = glGetError()) != GL_NO_ERROR) {
                    std::string msg = "glError: ";
                    msg += PCSX::GUI::glErrorToString(glError);
                    m_lastLuaErrors.push_back(msg);
                    gotGLerror = true;
                }
                if (gotGLerror) throw("OpenGL error while running Lua code");
            } catch (...) {
                L->push();
                L->setfield("Draw");
            }
        }
    }
    while (top < L->gettop()) {
        L->pop();
    }
    if (!m_show) return false;
    if (!ImGui::Begin(title.data(), &m_show)) return false;
    ImGui::Checkbox(_("Auto reload"), &m_autoreload);
    ImGui::SameLine();
    ImGui::Checkbox(_("Auto save"), &m_autosave);
    ImGui::SameLine();
    ImGui::Checkbox(_("Show all"), &m_showAll);
    auto contents = ImGui::GetContentRegionAvail();
    ImGuiStyle &style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = heightSeparator * 2 + 5 * ImGui::GetTextLineHeightWithSpacing();
    float width = contents.x / 3 - style.ItemInnerSpacing.x;
    gui->useMonoFont();
    if (m_showAll) {
        m_vertexShaderEditor.Render(_("Vertex Shader"), {width, -footerHeight}, true);
        ImGui::SameLine();
        m_pixelShaderEditor.Render(_("Pixel Shader"), {width, -footerHeight}, true);
        ImGui::SameLine();
        m_luaEditor.Render(_("Lua Invoker"), {width, -footerHeight}, true);
    } else {
        if (ImGui::BeginTabBar("MyTabBar")) {
            if (ImGui::BeginTabItem(_("Vertex Shader"))) {
                m_vertexShaderEditor.Render(_("Vertex Shader"), {0, -footerHeight}, true);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Pixel Shader"))) {
                m_pixelShaderEditor.Render(_("Pixel Shader"), {0, -footerHeight}, true);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Lua Invoker"))) {
                m_luaEditor.Render(_("Lua Invoker"), {0, -footerHeight}, true);
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

    return m_vertexShaderEditor.IsTextChanged() || m_pixelShaderEditor.IsTextChanged() || m_luaEditor.IsTextChanged();
}

void PCSX::Widgets::ShaderEditor::getRegistry(std::unique_ptr<Lua> &L) {
    L->push("SHADER_EDITOR");
    L->gettable(LUA_REGISTRYINDEX);
    if (L->isnil()) {
        L->pop();
        L->newtable();
        L->push("SHADER_EDITOR");
        L->copy(-2);
        L->settable(LUA_REGISTRYINDEX);
    }
}

void PCSX::Widgets::ShaderEditor::render(ImTextureID textureID, const ImVec2 &srcSize, const ImVec2 &dstSize) {
    if (m_shaderProgram == 0) {
        compile();
    }
    if (m_shaderProgram == 0) {
        ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
        return;
    }

    m_textureID = static_cast<GLuint>(reinterpret_cast<uintptr_t>(textureID));

    ImDrawList *drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);

    auto &L = g_emulator->m_lua;
    int top = L->gettop();
    getRegistry(L);
    L->push(m_index);
    L->gettable();
    if (L->isnil() || !L->istable()) {
        ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
    } else {
        L->push("Image");
        L->gettable();
        if (L->isfunction()) {
            L->copy(-2);
            L->setfenv();
            L->push(lua_Number(m_textureID));
            L->push(srcSize.x);
            L->push(srcSize.y);
            L->push(dstSize.x);
            L->push(dstSize.y);
            try {
                L->pcall(5);
                bool gotGLerror = false;
                GLenum glError = GL_NO_ERROR;
                while ((glError = glGetError()) != GL_NO_ERROR) {
                    std::string msg = "glError: ";
                    msg += PCSX::GUI::glErrorToString(glError);
                    m_lastLuaErrors.push_back(msg);
                    gotGLerror = true;
                }
                if (gotGLerror) throw("OpenGL error while running Lua code");
            } catch (...) {
                L->push();
                L->setfield("Image");
            }
        } else {
            ImGui::Image(textureID, dstSize, {0, 0}, {1, 1});
        }
    }
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
    while (top < L->gettop()) {
        L->pop();
    }
}

void PCSX::Widgets::ShaderEditor::imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    GLint imguiProgramID;
    glGetIntegerv(GL_CURRENT_PROGRAM, &imguiProgramID);

    GLint projMatrixLocation = glGetUniformLocation(imguiProgramID, "ProjMtx");

    GLfloat currentProjection[4][4];
    glGetUniformfv(imguiProgramID, projMatrixLocation, &currentProjection[0][0]);

    glUseProgram(m_shaderProgram);
    int proj = glGetUniformLocation(m_shaderProgram, "u_projMatrix");
    if (proj != -1) {
        glUniformMatrix4fv(proj, 1, GL_FALSE, &currentProjection[0][0]);
    }
    glBindTexture(GL_TEXTURE_2D, m_textureID);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

    auto &L = g_emulator->m_lua;
    int top = L->gettop();
    getRegistry(L);
    L->push(m_index);
    L->gettable();
    if (L->istable()) {
        L->push("BindAttributes");
        L->gettable();
        if (L->isfunction()) {
            L->copy(-2);
            L->setfenv();
            L->push(lua_Number(m_textureID));
            L->push(lua_Number(m_shaderProgram));
            try {
                L->pcall(2);
                bool gotGLerror = false;
                GLenum glError = GL_NO_ERROR;
                while ((glError = glGetError()) != GL_NO_ERROR) {
                    std::string msg = "glError: ";
                    msg += PCSX::GUI::glErrorToString(glError);
                    m_lastLuaErrors.push_back(msg);
                    gotGLerror = true;
                }
                if (gotGLerror) throw("OpenGL error while running Lua code");
            } catch (...) {
                L->push();
                L->setfield("BindAttributes");
            }
        }
    }
    while (top < L->gettop()) {
        L->pop();
    }

    PCSX::GUI::checkGL();
}
