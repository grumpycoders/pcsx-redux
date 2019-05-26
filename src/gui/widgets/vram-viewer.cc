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
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <utility>

#include "GL/gl3w.h"

#include "core/system.h"
#include "gui/widgets/vram-viewer.h"

#define GL_SHADER_VERSION "#version 300 es\n"

static const GLchar *s_defaultVertexShader = GL_SHADER_VERSION R"(
precision highp float;
in vec2 i_position;
in vec2 i_texUV;
uniform mat4 u_projMatrix;
out vec2 fragUV;

void main() {
    fragUV = i_texUV;
    gl_Position = u_projMatrix * vec4(i_position.xy, 0.0f, 1.0f);
}
)";

static const GLchar *s_defaultPixelShader = GL_SHADER_VERSION R"(
precision highp float;
uniform sampler2D u_vramTexture;
in vec2 fragUV;
out vec4 outColor;

void main() {
    outColor = texture(u_vramTexture, fragUV.st);
    outColor.a = 1.0f;
}
)";

void PCSX::Widgets::VRAMViewer::compileShader(const char *VS, const char *PS) {
    GLint status = 0;

    GLuint vertexShader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertexShader, 1, &VS, 0);
    glCompileShader(vertexShader);

    glGetShaderiv(vertexShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(vertexShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);
        glGetShaderInfoLog(vertexShader, maxLength, &maxLength, log);

        m_errorMessage = std::string(_("Vertex Shader compilation error:\n")) + log;

        free(log);
        glDeleteShader(vertexShader);
        return;
    }

    GLuint pixelShader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(pixelShader, 1, &PS, 0);
    glCompileShader(pixelShader);

    glGetShaderiv(pixelShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(pixelShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetShaderInfoLog(pixelShader, maxLength, &maxLength, log);

        m_errorMessage = std::string(_("Pixel Shader compilation error:\n")) + log;

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        return;
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

        m_errorMessage = std::string(_("Link error:\n")) + log;

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        return;
    }

    destroy();
    m_shaderProgram = shaderProgram;
    m_vertexShader = vertexShader;
    m_pixelShader = pixelShader;
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "u_vramTexture");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "u_projMatrix");
    m_attribLocationVtxPos = glGetAttribLocation(m_shaderProgram, "i_position");
    m_attribLocationVtxUV = glGetAttribLocation(m_shaderProgram, "i_texUV");
    m_attribLocationHovered = glGetUniformLocation(m_shaderProgram, "u_hovered");

    m_errorMessage = "";
}

void PCSX::Widgets::VRAMViewer::init() {
    m_vertexShaderEditor.SetText(s_defaultVertexShader);
    m_pixelShaderEditor.SetText(s_defaultPixelShader);
    compileShader(s_defaultVertexShader, s_defaultPixelShader);
}

void PCSX::Widgets::VRAMViewer::destroy() {
    if (m_shaderProgram) glDeleteProgram(m_shaderProgram);
    if (m_vertexShader) glDeleteShader(m_vertexShader);
    if (m_pixelShader) glDeleteShader(m_pixelShader);
}

void PCSX::Widgets::VRAMViewer::drawVRAM(unsigned int textureID, ImVec2 dimensions) {
    ImDrawList *drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);
    ImGui::Image((ImTextureID)textureID, dimensions, ImVec2(0, 0), ImVec2(1, 1));
    m_hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_None);
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
}

void PCSX::Widgets::VRAMViewer::drawEditor() {
    auto contents = ImGui::GetContentRegionAvail();
    ImGuiStyle &style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = heightSeparator * 2 + 5 * ImGui::GetTextLineHeightWithSpacing();
    float width = contents.x / 2 - style.ItemInnerSpacing.x;
    m_vertexShaderEditor.Render(_("Vertex Shader"), ImVec2(width, -footerHeight), true);
    ImGui::SameLine();
    m_pixelShaderEditor.Render(_("Pixel Shader"), ImVec2(width, -footerHeight), true);
    ImGui::BeginChild("Errors", ImVec2(0, 0), true);
    ImGui::Text("%s", m_errorMessage.c_str());
    ImGui::EndChild();

    if (m_vertexShaderEditor.IsTextChanged() || m_pixelShaderEditor.IsTextChanged()) {
        compileShader(m_vertexShaderEditor.GetText().c_str(), m_pixelShaderEditor.GetText().c_str());
    }
}

void PCSX::Widgets::VRAMViewer::imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    GLint imguiProgramID;
    glGetIntegerv(GL_CURRENT_PROGRAM, &imguiProgramID);

    GLint projMatrixLocation = glGetUniformLocation(imguiProgramID, "ProjMtx");

    GLfloat currentProjection[4][4];
    glGetUniformfv(imguiProgramID, projMatrixLocation, &currentProjection[0][0]);

    glUseProgram(m_shaderProgram);
    glUniform1i(m_attribLocationTex, 0);
    glUniformMatrix4fv(m_attribLocationProjMtx, 1, GL_FALSE, &currentProjection[0][0]);
    glUniform1i(m_attribLocationHovered, m_hovered);
    glEnableVertexAttribArray(m_attribLocationVtxPos);
    glEnableVertexAttribArray(m_attribLocationVtxUV);
    glVertexAttribPointer(m_attribLocationVtxPos, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, pos));
    glVertexAttribPointer(m_attribLocationVtxUV, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, uv));
}
