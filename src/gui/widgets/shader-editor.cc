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

#include "GL/gl3w.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "lua/luawrapper.h"

lua_Number PCSX::Widgets::ShaderEditor::s_index = 0;

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

    if (m_autoreload) {
        m_lastLuaErrors.clear();
        auto oldNormalPrinter = L->normalPrinter;
        auto oldErrorPrinter = L->errorPrinter;
        L->normalPrinter = [](const std::string &) {};
        L->errorPrinter = [this](const std::string &msg) { m_lastLuaErrors.push_back(msg); };
        int top = L->gettop();
        // grabbing the table where we'll store our shader invoker
        L->push("SHADER_EDITOR");
        L->gettable(LUA_REGISTRYINDEX);
        if (L->isnil()) {
            L->pop();
            L->newtable();
            L->push("SHADER_EDITOR");
            L->copy(-2);
            L->settable(LUA_REGISTRYINDEX);
        }
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
            L->load(getLuaText(), "pcsx.lua", false);
            L->copy(-2);
            L->setfenv(-2);
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
        // TODO
    }

    return shaderProgram;
}

bool PCSX::Widgets::ShaderEditor::draw(std::string_view title, GUI *gui) {
    if (!ImGui::Begin(title.data(), &m_show)) return false;
    ImGui::Checkbox(_("Auto reload"), &m_autoreload);
    ImGui::SameLine();
    ImGui::Checkbox(_("Auto save"), &m_autosave);
    auto contents = ImGui::GetContentRegionAvail();
    ImGuiStyle &style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = heightSeparator * 2 + 5 * ImGui::GetTextLineHeightWithSpacing();
    float width = contents.x / 3 - style.ItemInnerSpacing.x;
    gui->useMonoFont();
    m_vertexShaderEditor.Render(_("Vertex Shader"), ImVec2(width, -footerHeight), true);
    ImGui::SameLine();
    m_pixelShaderEditor.Render(_("Pixel Shader"), ImVec2(width, -footerHeight), true);
    ImGui::SameLine();
    m_luaEditor.Render(_("Lua Invoker"), ImVec2(width, -footerHeight), true);
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
