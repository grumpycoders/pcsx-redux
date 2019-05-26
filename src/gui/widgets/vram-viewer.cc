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

#include "gui/widgets/vram-viewer.h"

#define GL_SHADER_VERSION "#version 300 es\n"

static const GLchar *s_defaultVertexShader = GL_SHADER_VERSION R"(
precision highp float;
in vec2 position;
in vec2 texUV;
uniform mat4 projMatrix;
uniform uint hoveredIn;
out vec2 fragUV;

void main() {
    fragUV = texUV;
    gl_Position = projMatrix * vec4(position.xy, 0.0f, 1.0f);
}
)";

static const GLchar *s_defaultPixelShader = GL_SHADER_VERSION R"(
precision highp float;
uniform sampler2D vramTexture;
uniform bool hovered;
in vec2 fragUV;
out vec4 outColor;

void main() {
    outColor = texture(vramTexture, fragUV.st);
    outColor = vec4(1.0f) - outColor;
    outColor.a = 1.0f;
}
)";

std::string PCSX::Widgets::VRAMViewer::compileShader(const char *VS, const char *PS) {
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

        std::string error = log;

        free(log);
        glDeleteShader(vertexShader);

        return error;
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

        std::string error = log;

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);

        return error;
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

        std::string error = log;

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);

        return error;
    }

    destroy();
    m_shaderProgram = shaderProgram;
    m_vertexShader = vertexShader;
    m_pixelShader = pixelShader;
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "vramTexture");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "projMatrix");
    m_attribLocationVtxPos = glGetAttribLocation(m_shaderProgram, "position");
    m_attribLocationVtxUV = glGetAttribLocation(m_shaderProgram, "texUV");
    m_attribLocationHovered = glGetUniformLocation(m_shaderProgram, "hovered");
    return "";
}

void PCSX::Widgets::VRAMViewer::init() {
    compileShader(s_defaultVertexShader, s_defaultPixelShader);
    SDL_assert(m_shaderProgram);
    SDL_assert(m_attribLocationTex != -1);
    SDL_assert(m_attribLocationProjMtx != -1);
    SDL_assert(m_attribLocationVtxPos != -1);
    SDL_assert(m_attribLocationVtxUV != -1);
    SDL_assert(m_attribLocationHovered != -1);
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
